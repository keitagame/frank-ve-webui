# app.py
import os, re, json, shutil, subprocess, time
from flask import Flask, request, jsonify, abort
from jinja2 import Template
import libvirt
import yaml
from authlib.jose import JsonWebToken

from config import Config

def create_app():
    app = Flask(__name__)
    app.config.from_object(Config)

    # libvirt connection (keep a single long-lived connection)
    conn = libvirt.open(app.config['LIBVIRT_URI'])
    if conn is None:
        raise RuntimeError('Failed to connect to libvirt')

    # load domain XML template
    with open(os.path.join(os.path.dirname(__file__), 'templates', 'domain.xml.j2'), 'r', encoding='utf-8') as f:
        domain_tmpl = Template(f.read())

    # auth setup
    jwt = JsonWebToken(['RS256', 'HS256'])
    jwks_cache = {'keys': None, 'ts': 0}

    def load_jwks():
        # very small cache to avoid frequent fetch; replace with robust cache in prod
        if not app.config['OIDC_JWKS_URL']:
            return None
        if jwks_cache['keys'] and time.time() - jwks_cache['ts'] < 300:
            return jwks_cache['keys']
        import urllib.request
        with urllib.request.urlopen(app.config['OIDC_JWKS_URL']) as resp:
            data = json.loads(resp.read().decode('utf-8'))
            jwks_cache['keys'] = data
            jwks_cache['ts'] = time.time()
            return data

    def require_auth(role=None):
        if not app.config['REQUIRE_AUTH']:
            return {'roles': ['admin']}
        auth = request.headers.get('Authorization', '')
        if not auth.startswith('Bearer '):
            abort(401)
        token = auth.split(' ', 1)[1]
        # Try verification with JWKS, then fallback to unsecured decode only if configured (discouraged).
        jwks = load_jwks()
        claims = None
        try:
            claims = jwt.decode(token, jwks)
            claims.validate()
        except Exception:
            abort(401)
        # roles claim: "roles" or "realm_access" style
        roles = set()
        if isinstance(claims.get('roles'), list):
            roles = set(claims['roles'])
        elif isinstance(claims.get('realm_access'), dict):
            roles = set(claims['realm_access'].get('roles', []))
        aud = claims.get('aud')
        if aud and app.config['OIDC_AUDIENCE'] and app.config['OIDC_AUDIENCE'] not in (aud if isinstance(aud, list) else [aud]):
            abort(401)
        ctx = {'sub': claims.get('sub'), 'roles': roles}
        if role == 'admin' and not (roles & app.config['ROLES_ADMIN']):
            abort(403)
        if role == 'ops' and not (roles & (app.config['ROLES_ADMIN'] | app.config['ROLES_OPERATOR'])):
            abort(403)
        return ctx

    # helpers
    def images_dir():
        return app.config['IMAGES_DIR']

    def disk_path(name):
        return os.path.join(images_dir(), f'{name}.qcow2')

    def seed_iso_path(name):
        return os.path.join(images_dir(), f'{name}-seed.iso')

    def ensure_dir(path):
        os.makedirs(path, exist_ok=True)

    def domain_by_name(name):
        try:
            return conn.lookupByName(name)
        except libvirt.libvirtError:
            return None

    def parse_vnc_port(xml):
        m = re.search(r"<graphics\s+type='vnc'[^>]*port='(\d+)'", xml)
        if m:
            return int(m.group(1))
        # autoportの場合、libvirtが割当済みならXMLに出る。未起動ならNone。
        return None

    def build_domain_xml(params):
        return domain_tmpl.render(**params)

    def create_cloud_init_seed(name, user_data_text, meta_data_text):
        ensure_dir(images_dir())
        ud_file = os.path.join(images_dir(), f'{name}-user-data.yaml')
        md_file = os.path.join(images_dir(), f'{name}-meta-data.yaml')
        with open(ud_file, 'w', encoding='utf-8') as f:
            f.write(user_data_text)
        with open(md_file, 'w', encoding='utf-8') as f:
            f.write(meta_data_text)
        subprocess.check_call(['cloud-localds', seed_iso_path(name), ud_file, md_file])
        return seed_iso_path(name)

    # routes
    @app.route('/api/v1/health', methods=['GET'])
    def health():
        return jsonify({'status': 'ok'})

    @app.route('/api/v1/vms', methods=['GET'])
    def list_vms():
        require_auth('ops')
        domains = conn.listAllDomains()
        res = []
        for d in domains:
            info = d.info()  # [state, maxMem, memory, nrVirtCpu, cpuTime]
            res.append({
                'name': d.name(),
                'uuid': d.UUIDString(),
                'state': int(info[0]),
                'memory_kib': int(info[1]),
                'vcpus': int(info[3]),
            })
        return jsonify(res)

    @app.route('/api/v1/vms', methods=['POST'])
    def create_vm():
        require_auth('ops')
        body = request.get_json(force=True, silent=True) or {}
        name = body.get('name')
        if not name:
            abort(400, description='name is required')
        if domain_by_name(name):
            abort(409, description='vm already exists')

        vcpus = int(body.get('vcpus', 2))
        memory_mb = int(body.get('memory_mb', 2048))
        memory_kib = memory_mb * 1024
        disk_gb = int(body.get('disk_gb', 20))
        bridge = body.get('bridge', app.config['DEFAULT_BRIDGE'])
        iso_path = body.get('iso_path', '') or None

        # disk
        ensure_dir(images_dir())
        dpath = disk_path(name)
        subprocess.check_call(['qemu-img', 'create', '-f', 'qcow2', dpath, f'{disk_gb}G'])

        # cloud-init (optional)
        seed_path = None
        cud = body.get('cloud_user_data')
        cmd = body.get('cloud_meta_data')
        if cud and cmd:
            seed_path = create_cloud_init_seed(name, cud, cmd)

        # domain XML
        xml = build_domain_xml({
            'name': name, 'memory': memory_kib, 'vcpus': vcpus,
            'disk_path': dpath, 'bridge': bridge,
            'iso_path': iso_path or seed_path,  # どちらかが指定されていればCDROMにセット
            'vnc_autoport': 'yes'
        })
        dom = conn.defineXML(xml)
        dom.create()
        return jsonify({'name': name, 'disk': dpath})

    @app.route('/api/v1/vms/<name>', methods=['GET'])
    def get_vm(name):
        require_auth('ops')
        dom = domain_by_name(name)
        if not dom:
            abort(404)
        info = dom.info()
        return jsonify({
            'name': dom.name(),
            'uuid': dom.UUIDString(),
            'state': int(info[0]),
            'memory_kib': int(info[1]),
            'vcpus': int(info[3]),
            'xml': dom.XMLDesc()  # 必要に応じて省略可能
        })

    @app.route('/api/v1/vms/<name>/power', methods=['POST'])
    def power(name):
        require_auth('ops')
        dom = domain_by_name(name)
        if not dom:
            abort(404)
        action = (request.get_json(force=True) or {}).get('action')
        if action == 'start':
            dom.create()
        elif action == 'shutdown':
            dom.shutdown()
        elif action == 'reboot':
            dom.reboot(libvirt.VIR_DOMAIN_REBOOT_DEFAULT)
        elif action == 'destroy':
            dom.destroy()
        else:
            abort(400, description='invalid action')
        return ('', 204)

    @app.route('/api/v1/vms/<name>', methods=['DELETE'])
    def delete_vm(name):
        require_auth('admin')
        dom = domain_by_name(name)
        # stop/destroy if running
        if dom:
            try:
                if dom.isActive():
                    dom.destroy()
                dom.undefineFlags(libvirt.VIR_DOMAIN_UNDEFINE_SNAPSHOTS_METADATA)
            except libvirt.libvirtError:
                pass
        # delete disks
        if app.config['ALLOW_DISK_DELETE']:
            dp = disk_path(name)
            if os.path.exists(dp):
                os.remove(dp)
            sp = seed_iso_path(name)
            if os.path.exists(sp):
                os.remove(sp)
            # remove any cloud-init temp files
            for suffix in ('-user-data.yaml', '-meta-data.yaml'):
                p = os.path.join(images_dir(), f'{name}{suffix}')
                if os.path.exists(p):
                    os.remove(p)
        return ('', 204)

    @app.route('/api/v1/vms/<name>/console', methods=['GET'])
    def console(name):
        require_auth('ops')
        dom = domain_by_name(name)
        if not dom:
            abort(404)
        xml = dom.XMLDesc()
        port = parse_vnc_port(xml)
        if port is None:
            abort(409, description='vnc port not assigned; start the VM first')
        idx = port - 5900
        base = app.config['NOVNC_PUBLIC_BASE'].rstrip('/')
        # 例: /vnc/0/vnc.html?host=vm.local&port=443&path=/vnc/0/
        novnc_url = f"{base}/{idx}/vnc.html?path={base}/{idx}/"
        return jsonify({'novnc_url': novnc_url, 'vnc_port': port})

    @app.route('/api/v1/vms/<name>/snapshot', methods=['POST'])
    def snapshot(name):
        require_auth('ops')
        dom = domain_by_name(name)
        if not dom:
            abort(404)
        body = request.get_json(force=True) or {}
        snapname = body.get('name', f'snap-{int(time.time())}')
        try:
            dom.snapshotCreateXML(f"""
            <domainsnapshot>
              <name>{snapname}</name>
            </domainsnapshot>
            """, 0)
        except libvirt.libvirtError as e:
            abort(409, description=str(e))
        return jsonify({'snapshot': snapname})

    @app.route('/api/v1/vms/<name>/resize', methods=['POST'])
    def resize_disk(name):
        require_auth('admin')
        body = request.get_json(force=True) or {}
        new_size_gb = int(body.get('disk_gb', 0))
        if new_size_gb <= 0:
            abort(400, description='disk_gb required')
        dp = disk_path(name)
        if not os.path.exists(dp):
            abort(404, description='disk not found')
        subprocess.check_call(['qemu-img', 'resize', dp, f'{new_size_gb}G'])
        return ('', 204)

    # error handlers (compact JSON)
    @app.errorhandler(400)
    @app.errorhandler(401)
    @app.errorhandler(403)
    @app.errorhandler(404)
    @app.errorhandler(409)
    def err(e):
        return jsonify({'error': getattr(e, 'description', str(e))}), e.code

    return app

# Dev entrypoint
if __name__ == '__main__':
    app = create_app()
    app.run(host='127.0.0.1', port=8000)
