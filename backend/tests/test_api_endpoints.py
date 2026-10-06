"""
Tests for SecureGate REST API Endpoints
"""
import json


def test_health_endpoint(client):
    res = client.get('/api/health')
    assert res.status_code == 200
    data = res.get_json()
    assert data['status'] == 'healthy'
    assert 'database' in data


def test_projects_flow(client):
    # 1. Create a project
    res = client.post('/api/projects', json={
        'name': 'Test Target App',
        'target_url': 'http://localhost:3000',
        'description': 'Dev target for testing'
    })
    assert res.status_code == 201
    proj_id = res.get_json()['project']['id']

    # 2. Get projects
    res = client.get('/api/projects')
    assert res.status_code == 200
    assert any(p['id'] == proj_id for p in res.get_json()['projects'])

    # 3. Get single project
    res = client.get(f'/api/projects/{proj_id}')
    assert res.status_code == 200
    assert res.get_json()['project']['name'] == 'Test Target App'


def test_scan_upload_and_release_evaluation(client):
    # Setup project
    res_proj = client.post('/api/projects', json={
        'name': 'Vulnerable Store API',
        'target_url': 'http://localhost:3000'
    })
    project_id = res_proj.get_json()['project']['id']

    # Upload ZAP JSON report containing 1 High SQL Injection finding
    zap_report = {
        "@version": "2.14.0",
        "site": [
            {
                "@name": "http://localhost:3000",
                "alerts": [
                    {
                        "alert": "SQL Injection",
                        "riskcode": "3",
                        "confidence": "3",
                        "desc": "SQL injection detected.",
                        "url": "http://localhost:3000/api/users",
                        "param": "user_id",
                        "cweid": "89",
                        "solution": "Use parameterized queries"
                    }
                ]
            }
        ]
    }

    res_upload = client.post('/api/scans/upload', json={
        'project_id': project_id,
        'report': zap_report,
        'scan_identifier': 'TEST-SCAN-001'
    })
    assert res_upload.status_code == 201
    scan_data = res_upload.get_json()['scan']
    assert scan_data['release_status'] == 'BLOCK'
    assert scan_data['high_count'] == 1
    assert scan_data['total_findings'] == 1

    scan_id = scan_data['id']

    # Test dashboard endpoint
    res_dash = client.get(f'/api/dashboard?project_id={project_id}')
    assert res_dash.status_code == 200
    dash_data = res_dash.get_json()
    assert dash_data['release_gate']['status'] == 'BLOCK'
    assert dash_data['metrics']['high'] == 1

    # Test findings endpoint
    res_findings = client.get(f'/api/findings?scan_id={scan_id}')
    assert res_findings.status_code == 200
    findings = res_findings.get_json()['findings']
    assert len(findings) == 1
    finding_id = findings[0]['id']

    # Update finding status
    res_patch = client.patch(f'/api/findings/{finding_id}', json={'status': 'reviewed'})
    assert res_patch.status_code == 200
    assert res_patch.get_json()['finding']['status'] == 'reviewed'

    # Test releases endpoint
    res_rel = client.get(f'/api/releases?project_id={project_id}')
    assert res_rel.status_code == 200
    releases = res_rel.get_json()['releases']
    assert len(releases) >= 1
    assert releases[0]['status'] == 'BLOCK'

    # Test reports endpoint
    res_rep = client.get(f'/api/reports/{scan_id}')
    assert res_rep.status_code == 200
    report_data = res_rep.get_json()['report']
    assert report_data['release_status'] == 'BLOCK'

    # Test HTML report
    res_rep_html = client.get(f'/api/reports/{scan_id}/html')
    assert res_rep_html.status_code == 200
    assert b"SecureGate" in res_rep_html.data


def test_settings_endpoint(client):
    res = client.get('/api/settings')
    assert res.status_code == 200
    data = res.get_json()['settings']
    assert 'release_policy' in data

    # Update settings
    res_put = client.put('/api/settings', json={
        'release_policy': {
            'critical': 'BLOCK',
            'high': 'BLOCK',
            'medium': 'BLOCK',
            'low': 'REVIEW',
            'informational': 'PASS'
        },
        'environment': 'staging'
    })
    assert res_put.status_code == 200
    updated = res_put.get_json()['settings']
    assert updated['release_policy']['medium'] == 'BLOCK'
    assert updated['environment'] == 'staging'


def test_ai_explain_fallback(client):
    res = client.post('/api/ai/explain', json={
        'finding': {
            'name': 'Cross Site Scripting (XSS)',
            'severity': 'High',
            'owasp_category': 'A03:2021 - Injection',
            'cwe_id': 'CWE-79',
            'url': 'http://localhost:3000/profile',
            'parameter': 'username'
        }
    })
    assert res.status_code == 200
    data = res.get_json()
    assert 'result' in data
    assert 'analysis' in data['result']
    assert 'plain_english_explanation' in data['result']['analysis']
