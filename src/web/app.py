from flask import Flask, render_template_string, jsonify, request, session, redirect, url_for, send_file
from flask_cors import CORS
from src.utils.database import db, EmailCheck, CheckResult, StatusEnum, RiskLevelEnum, User
from src.utils.logger import logger
from config.config import config
import os
import glob
from functools import wraps


def create_app():
    """Create and configure Flask application"""
    app = Flask(__name__)
    app.config['SECRET_KEY'] = config.SECRET_KEY
    CORS(app, origins=['https://mailverify.tlx.zone'], supports_credentials=True)

    # Admin authentication decorator (uses Flask session cookie)
    def admin_required(f):
        @wraps(f)
        def decorated_function(*args, **kwargs):
            if not session.get('admin_authenticated'):
                return jsonify({'error': 'Unauthorized'}), 401
            return f(*args, **kwargs)
        return decorated_function

    @app.route('/api/login', methods=['POST'])
    def api_login():
        """Authenticate admin via password in POST body"""
        # Accept both JSON and form data (form data avoids CORS preflight)
        if request.is_json:
            data = request.get_json(silent=True) or {}
            password = data.get('password', '')
        else:
            password = request.form.get('password', '')
        if password == config.ADMIN_PASSWORD:
            session['admin_authenticated'] = True
            return jsonify({'success': True})
        return jsonify({'error': 'Invalid password'}), 401

    @app.route('/api/logout', methods=['POST'])
    def api_logout():
        """Logout admin"""
        session.clear()
        return jsonify({'success': True})

    @app.route('/')
    def index():
        """Landing page with project info"""
        return render_template_string(LANDING_TEMPLATE)

    @app.route('/api/checks')
    @admin_required
    def get_checks():
        """Get all email checks"""
        db_session = db.get_session()
        try:
            checks = db_session.query(EmailCheck).order_by(EmailCheck.created_at.desc()).limit(100).all()

            data = []
            for check in checks:
                data.append({
                    'id': check.id,
                    'created_at': check.created_at.isoformat(),
                    'from_address': check.from_address,
                    'subject': check.subject,
                    'status': check.status.value,
                    'risk_level': check.risk_level.value if check.risk_level else None,
                    'overall_score': check.overall_score
                })

            return jsonify(data)

        except Exception as e:
            logger.error(f"API error: {e}")
            return jsonify({'error': 'Internal server error'}), 500
        finally:
            db_session.close()

    @app.route('/api/check/<int:check_id>')
    @admin_required
    def get_check_details(check_id):
        """Get detailed check information"""
        db_session = db.get_session()
        try:
            check = db_session.query(EmailCheck).filter_by(id=check_id).first()

            if not check:
                return jsonify({'error': 'Not found'}), 404

            result = db_session.query(CheckResult).filter_by(check_id=check_id).first()

            data = {
                'id': check.id,
                'created_at': check.created_at.isoformat(),
                'from_address': check.from_address,
                'from_name': check.from_name,
                'subject': check.subject,
                'status': check.status.value,
                'risk_level': check.risk_level.value if check.risk_level else None,
                'overall_score': check.overall_score,
                'has_report': bool(check.report_pdf_path)
            }

            if result:
                data['results'] = {
                    'dkim_valid': result.dkim_valid,
                    'spf_valid': result.spf_valid,
                    'dmarc_valid': result.dmarc_valid,
                    'domain_age_days': result.domain_age_days,
                    'ip_blacklisted': result.ip_blacklisted,
                    'claude_verdict': result.claude_verdict
                }

            return jsonify(data)

        except Exception as e:
            logger.error(f"API error: {e}")
            return jsonify({'error': 'Internal server error'}), 500
        finally:
            db_session.close()

    @app.route('/api/check/<int:check_id>/report')
    @admin_required
    def get_report(check_id):
        """Get PDF report for a check"""
        db_session = db.get_session()
        try:
            check = db_session.query(EmailCheck).filter_by(id=check_id).first()

            if not check:
                return jsonify({'error': 'Check not found'}), 404

            if not check.report_pdf_path or not os.path.exists(check.report_pdf_path):
                return jsonify({'error': 'Report not found'}), 404

            # Path traversal protection: ensure path is within REPORTS_DIR
            real_path = os.path.realpath(check.report_pdf_path)
            allowed_dir = os.path.realpath(config.REPORTS_DIR)
            if not real_path.startswith(allowed_dir + os.sep):
                logger.warning(f"Path traversal attempt: {check.report_pdf_path}")
                return jsonify({'error': 'Report not found'}), 404

            return send_file(
                real_path,
                mimetype='application/pdf',
                as_attachment=False,
                download_name=f'report_{check_id}.pdf'
            )

        except Exception as e:
            logger.error(f"Failed to serve report: {e}")
            return jsonify({'error': 'Internal server error'}), 500
        finally:
            db_session.close()

    @app.route('/api/stats')
    @admin_required
    def get_stats():
        """Get statistics"""
        db_session = db.get_session()
        try:
            total = db_session.query(EmailCheck).count()
            completed = db_session.query(EmailCheck).filter_by(status=StatusEnum.COMPLETED).count()
            processing = db_session.query(EmailCheck).filter_by(status=StatusEnum.PROCESSING).count()

            green = db_session.query(EmailCheck).filter_by(risk_level=RiskLevelEnum.GREEN).count()
            yellow = db_session.query(EmailCheck).filter_by(risk_level=RiskLevelEnum.YELLOW).count()
            red = db_session.query(EmailCheck).filter_by(risk_level=RiskLevelEnum.RED).count()

            return jsonify({
                'total': total,
                'completed': completed,
                'processing': processing,
                'risk_distribution': {
                    'green': green,
                    'yellow': yellow,
                    'red': red
                }
            })

        except Exception as e:
            logger.error(f"API error: {e}")
            return jsonify({'error': 'Internal server error'}), 500
        finally:
            db_session.close()

    @app.route('/api/check/<int:check_id>/delete', methods=['POST'])
    @admin_required
    def delete_check(check_id):
        """Delete a check"""
        db_session = db.get_session()
        try:
            check = db_session.query(EmailCheck).filter_by(id=check_id).first()

            if not check:
                return jsonify({'error': 'Not found'}), 404

            # Delete associated result
            db_session.query(CheckResult).filter_by(check_id=check_id).delete()

            # Delete files if they exist
            if check.raw_email_path and os.path.exists(check.raw_email_path):
                os.remove(check.raw_email_path)
            if check.report_pdf_path and os.path.exists(check.report_pdf_path):
                os.remove(check.report_pdf_path)

            # Delete check record
            db_session.delete(check)
            db_session.commit()

            logger.info(f"Deleted check {check_id}")
            return jsonify({'success': True})

        except Exception as e:
            logger.error(f"API error: {e}")
            return jsonify({'error': 'Internal server error'}), 500
        finally:
            db_session.close()

    @app.route('/api/check/<int:check_id>/recheck', methods=['POST'])
    @admin_required
    def recheck_email(check_id):
        """Recheck an email"""
        db_session = db.get_session()
        try:
            check = db_session.query(EmailCheck).filter_by(id=check_id).first()

            if not check:
                return jsonify({'error': 'Not found'}), 404

            # Check if raw email file exists
            if not check.raw_email_path or not os.path.exists(check.raw_email_path):
                return jsonify({'error': 'Raw email file not found'}), 404

            # Read raw email
            with open(check.raw_email_path, 'rb') as f:
                raw_email = f.read()

            # Delete old results
            db_session.query(CheckResult).filter_by(check_id=check_id).delete()

            # Reset check status
            check.status = StatusEnum.PENDING
            check.overall_score = 0
            check.risk_level = None
            db_session.commit()

            # Process email asynchronously
            from src.services.orchestrator import Orchestrator
            orchestrator = Orchestrator()

            # Run in background thread
            import threading
            thread = threading.Thread(
                target=orchestrator.process_email,
                args=(check.message_id, raw_email)
            )
            thread.daemon = True
            thread.start()

            logger.info(f"Rechecking email {check_id}")
            return jsonify({'success': True, 'message': 'Recheck started'})

        except Exception as e:
            logger.error(f"API error: {e}")
            return jsonify({'error': 'Internal server error'}), 500
        finally:
            db_session.close()

    @app.route('/admin/login', methods=['POST'])
    def admin_login_post():
        """Handle HTML form login — no fetch, no CORS, no Cloudflare blocks"""
        password = request.form.get('password', '')
        if password == config.ADMIN_PASSWORD:
            session['admin_authenticated'] = True
            return redirect('/admin')
        return render_template_string(ADMIN_DASHBOARD_TEMPLATE, login_error='Неверный пароль',
                                      checks=[], stats={}, users=[])

    @app.route('/admin/delete/<int:check_id>', methods=['POST'])
    def admin_delete_check(check_id):
        """Delete check via HTML form POST"""
        if not session.get('admin_authenticated'):
            return redirect('/admin')
        db_session = db.get_session()
        try:
            check = db_session.query(EmailCheck).filter_by(id=check_id).first()
            if check:
                db_session.query(CheckResult).filter_by(check_id=check_id).delete()
                if check.raw_email_path and os.path.exists(check.raw_email_path):
                    os.remove(check.raw_email_path)
                if check.report_pdf_path and os.path.exists(check.report_pdf_path):
                    os.remove(check.report_pdf_path)
                db_session.delete(check)
                db_session.commit()
                logger.info(f"Deleted check {check_id}")
        except Exception as e:
            logger.error(f"Delete error: {e}")
        finally:
            db_session.close()
        return redirect('/admin')

    @app.route('/admin/recheck/<int:check_id>', methods=['POST'])
    def admin_recheck(check_id):
        """Recheck email via HTML form POST"""
        if not session.get('admin_authenticated'):
            return redirect('/admin')
        db_session = db.get_session()
        try:
            check = db_session.query(EmailCheck).filter_by(id=check_id).first()
            if check and check.raw_email_path and os.path.exists(check.raw_email_path):
                with open(check.raw_email_path, 'rb') as f:
                    raw_email = f.read()
                db_session.query(CheckResult).filter_by(check_id=check_id).delete()
                check.status = StatusEnum.PENDING
                check.overall_score = 0
                check.risk_level = None
                db_session.commit()
                from src.services.orchestrator import Orchestrator
                import threading
                thread = threading.Thread(target=Orchestrator().process_email,
                                          args=(check.message_id, raw_email))
                thread.daemon = True
                thread.start()
                logger.info(f"Recheck started for {check_id}")
        except Exception as e:
            logger.error(f"Recheck error: {e}")
        finally:
            db_session.close()
        return redirect('/admin')

    @app.route('/admin')
    def admin_panel():
        """Admin dashboard with checks and admin tools"""
        if not session.get('admin_authenticated'):
            return render_template_string(ADMIN_DASHBOARD_TEMPLATE, login_error=None,
                                          checks=[], stats={}, users=[])
        db_session = db.get_session()
        try:
            checks = db_session.query(EmailCheck).order_by(EmailCheck.created_at.desc()).limit(100).all()
            checks_data = [{
                'id': c.id,
                'created_at': c.created_at.strftime('%d.%m.%y %H:%M'),
                'from_address': c.from_address or '-',
                'subject': (c.subject or '-')[:60],
                'status': c.status.value,
                'risk_level': c.risk_level.value if c.risk_level else None,
                'overall_score': c.overall_score or '-',
                'has_report': bool(c.report_pdf_path)
            } for c in checks]

            total = db_session.query(EmailCheck).count()
            completed = db_session.query(EmailCheck).filter_by(status=StatusEnum.COMPLETED).count()
            processing = db_session.query(EmailCheck).filter_by(status=StatusEnum.PROCESSING).count()
            from src.utils.database import RiskLevelEnum as RLE
            green = db_session.query(EmailCheck).filter_by(risk_level=RLE.GREEN).count()
            yellow = db_session.query(EmailCheck).filter_by(risk_level=RLE.YELLOW).count()
            red = db_session.query(EmailCheck).filter_by(risk_level=RLE.RED).count()
            stats = {'total': total, 'completed': completed, 'processing': processing,
                     'green': green, 'yellow': yellow, 'red': red}

            users = db_session.query(User).all()
            users_data = [{'id': u.id, 'username': u.username, 'is_admin': u.is_admin,
                           'created_at': u.created_at.strftime('%d.%m.%Y %H:%M')} for u in users]
        except Exception as e:
            logger.error(f"Admin panel data error: {e}")
            checks_data, stats, users_data = [], {}, []
        finally:
            db_session.close()

        return render_template_string(ADMIN_DASHBOARD_TEMPLATE, login_error=None,
                                      checks=checks_data, stats=stats, users=users_data)

    @app.route('/admin/clear-database', methods=['POST'])
    def admin_clear_database_form():
        """Clear database via HTML form POST"""
        if not session.get('admin_authenticated'):
            return redirect('/admin')
        db_session = db.get_session()
        try:
            db_session.query(CheckResult).delete()
            db_session.query(EmailCheck).delete()
            db_session.commit()
            for f in glob.glob(os.path.join(config.ATTACHMENTS_DIR, '*.eml')) + \
                      glob.glob(os.path.join(config.REPORTS_DIR, '*.pdf')):
                try: os.remove(f)
                except: pass
            logger.info("Admin cleared all data via form")
        except Exception as e:
            logger.error(f"Clear DB error: {e}")
        finally:
            db_session.close()
        return redirect('/admin')

    @app.route('/admin/create-user', methods=['POST'])
    def admin_create_user_form():
        """Create user via HTML form POST"""
        if not session.get('admin_authenticated'):
            return redirect('/admin')
        db_session = db.get_session()
        try:
            username = request.form.get('username', '').strip()
            password = request.form.get('password', '').strip()
            is_admin = bool(request.form.get('is_admin'))
            if username and password:
                existing = db_session.query(User).filter_by(username=username).first()
                if not existing:
                    user = User(username=username, is_admin=is_admin)
                    user.set_password(password)
                    db_session.add(user)
                    db_session.commit()
                    logger.info(f"Created user: {username}")
        except Exception as e:
            logger.error(f"Create user error: {e}")
        finally:
            db_session.close()
        return redirect('/admin')

    @app.route('/api/admin/clear-database', methods=['POST'])
    @admin_required
    def admin_clear_database():
        """Clear all database records and files"""
        db_session = db.get_session()
        try:
            email_checks_count = db_session.query(EmailCheck).count()
            check_results_count = db_session.query(CheckResult).count()

            db_session.query(CheckResult).delete()
            db_session.query(EmailCheck).delete()
            db_session.commit()

            attachments = glob.glob(os.path.join(config.ATTACHMENTS_DIR, '*.eml'))
            reports = glob.glob(os.path.join(config.REPORTS_DIR, '*.pdf'))

            for file in attachments + reports:
                try:
                    os.remove(file)
                except Exception:
                    pass

            logger.info(f"Admin cleared database: {email_checks_count} checks, {check_results_count} results")

            return jsonify({
                'success': True,
                'deleted': {
                    'checks': email_checks_count,
                    'results': check_results_count,
                    'files': len(attachments) + len(reports)
                }
            })

        except Exception as e:
            logger.error(f"Admin API error: {e}")
            return jsonify({'error': 'Internal server error'}), 500
        finally:
            db_session.close()

    @app.route('/api/admin/create-user', methods=['POST'])
    @admin_required
    def admin_create_user():
        """Create a new user"""
        db_session = db.get_session()
        try:
            data = request.get_json()
            username = data.get('username')
            password = data.get('password')
            is_admin = data.get('is_admin', False)

            if not username or not password:
                return jsonify({'error': 'Username and password required'}), 400

            existing = db_session.query(User).filter_by(username=username).first()
            if existing:
                return jsonify({'error': 'User already exists'}), 400

            user = User(username=username, is_admin=is_admin)
            user.set_password(password)
            db_session.add(user)
            db_session.commit()

            logger.info(f"Admin created user: {username}")
            return jsonify({'success': True, 'username': username})

        except Exception as e:
            logger.error(f"Admin API error: {e}")
            return jsonify({'error': 'Internal server error'}), 500
        finally:
            db_session.close()

    @app.route('/api/admin/users', methods=['GET'])
    @admin_required
    def admin_list_users():
        """List all users"""
        db_session = db.get_session()
        try:
            users = db_session.query(User).all()

            data = []
            for user in users:
                data.append({
                    'id': user.id,
                    'username': user.username,
                    'is_admin': user.is_admin,
                    'created_at': user.created_at.isoformat()
                })

            return jsonify(data)

        except Exception as e:
            logger.error(f"Admin API error: {e}")
            return jsonify({'error': 'Internal server error'}), 500
        finally:
            db_session.close()

    return app


LANDING_TEMPLATE = '''
<!DOCTYPE html>
<html lang="ru">
<head>
    <title>Mail Address Verifier</title>
    <meta charset="utf-8">
    <meta name="viewport" content="width=device-width, initial-scale=1">
    <link rel="stylesheet" href="https://cdnjs.cloudflare.com/ajax/libs/font-awesome/6.4.0/css/all.min.css">
    <style>
        :root {
            --blue: #3498db; --green: #27ae60; --yellow: #f39c12;
            --red: #e74c3c; --dark: #2c3e50; --bg: #f0f2f5;
            --card: #fff; --border: #e8ecf1;
        }
        * { margin: 0; padding: 0; box-sizing: border-box; }
        body { font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif; background: var(--bg); color: #333; line-height: 1.6; }

        /* Hero */
        .hero { background: linear-gradient(135deg, var(--dark) 0%, #1a252f 100%); color: #fff; padding: 60px 20px 50px; text-align: center; }
        .hero-logo { margin-bottom: 20px; }
        .hero-logo svg { width: 80px; height: 80px; }
        .hero h1 { font-size: 32px; margin-bottom: 12px; font-weight: 700; }
        .hero p { font-size: 16px; color: #b0bec5; max-width: 600px; margin: 0 auto 24px; }
        .hero-btn { display: inline-block; padding: 12px 28px; background: var(--blue); color: #fff; text-decoration: none; border-radius: 8px; font-weight: 600; font-size: 14px; transition: background .2s; }
        .hero-btn:hover { background: #2980b9; }

        .container { max-width: 900px; margin: 0 auto; padding: 30px 20px; }

        /* Section */
        .section { margin-bottom: 32px; }
        .section h2 { font-size: 22px; color: var(--dark); margin-bottom: 16px; padding-bottom: 8px; border-bottom: 2px solid var(--blue); display: inline-block; }
        .section p { margin-bottom: 12px; color: #555; }

        /* Feature grid */
        .features { display: grid; grid-template-columns: repeat(3, 1fr); gap: 16px; margin-top: 16px; }
        .feature { background: var(--card); border-radius: 10px; padding: 20px; box-shadow: 0 1px 3px rgba(0,0,0,.08); text-align: center; }
        .feature i { font-size: 28px; color: var(--blue); margin-bottom: 10px; display: block; }
        .feature h3 { font-size: 14px; color: var(--dark); margin-bottom: 6px; }
        .feature p { font-size: 13px; color: #777; margin: 0; }

        /* Steps */
        .steps { counter-reset: step; }
        .step { background: var(--card); border-radius: 10px; padding: 20px 20px 20px 60px; margin-bottom: 12px; box-shadow: 0 1px 3px rgba(0,0,0,.08); position: relative; }
        .step::before { counter-increment: step; content: counter(step); position: absolute; left: 18px; top: 18px; width: 30px; height: 30px; background: var(--blue); color: #fff; border-radius: 50%; display: flex; align-items: center; justify-content: center; font-weight: 700; font-size: 14px; }
        .step h3 { font-size: 15px; color: var(--dark); margin-bottom: 6px; }
        .step p { font-size: 13px; color: #666; margin: 0; }

        /* EML box */
        .eml-box { background: #fff3cd; border: 1px solid #ffc107; border-radius: 10px; padding: 20px; margin-top: 20px; }
        .eml-box h3 { color: #856404; font-size: 16px; margin-bottom: 10px; }
        .eml-box p { color: #856404; font-size: 13px; margin-bottom: 8px; }
        .eml-box ul { margin: 8px 0 0 20px; color: #856404; font-size: 13px; }
        .eml-box li { margin-bottom: 6px; }
        .eml-box code { background: rgba(0,0,0,.08); padding: 2px 6px; border-radius: 3px; font-size: 12px; }

        /* Clients table */
        .clients-table { width: 100%; border-collapse: collapse; margin-top: 12px; font-size: 13px; }
        .clients-table th { background: var(--dark); color: #fff; padding: 10px 14px; text-align: left; }
        .clients-table td { padding: 10px 14px; border-bottom: 1px solid var(--border); }
        .clients-table tr:hover { background: #f8f9fb; }

        /* Risk legend */
        .risk-legend { display: flex; gap: 20px; margin-top: 16px; flex-wrap: wrap; }
        .risk-item { display: flex; align-items: center; gap: 8px; font-size: 14px; }
        .risk-dot { width: 14px; height: 14px; border-radius: 50%; }
        .risk-dot.g { background: var(--green); }
        .risk-dot.y { background: var(--yellow); }
        .risk-dot.r { background: var(--red); }

        /* Footer */
        .footer { text-align: center; padding: 20px; color: #aaa; font-size: 12px; border-top: 1px solid var(--border); margin-top: 20px; }

        @media (max-width: 768px) {
            .hero { padding: 40px 16px 36px; }
            .hero h1 { font-size: 24px; }
            .container { padding: 20px 14px; }
            .features { grid-template-columns: 1fr; }
            .clients-table { font-size: 12px; }
            .clients-table th, .clients-table td { padding: 8px 10px; }
        }
    </style>
</head>
<body>
    <div class="hero">
        <div class="hero-logo"><svg enable-background="new 0 0 497 497" viewBox="0 0 497 497" xmlns="http://www.w3.org/2000/svg"><g><path d="m248.486 6.243v19.897l-74.235 5.027-78.815-5.027v-19.897c0-3.448 2.795-6.243 6.243-6.243h140.564c3.448 0 6.243 2.795 6.243 6.243z" fill="#7ca1b1"/><path d="m248.49 6.24v19.9l-32 2v-21.9c0-3.45-2.8-6.24-6.25-6.24h32c3.45 0 6.25 2.79 6.25 6.24z" fill="#678d98"/><path d="m334.886 56.41v402.42c0 16.72-13.55 30.27-30.27 30.27h-265.31c-16.72 0-30.28-13.55-30.28-30.27v-402.42c0-16.72 13.56-30.27 30.28-30.27h15.975l116.684 7.694 113.985-7.694h18.666c16.72 0 30.27 13.55 30.27 30.27z" fill="#5986cb"/><path d="m334.89 56.41v402.42c0 16.72-13.55 30.27-30.27 30.27h-18.67c16.72 0 30.27-13.55 30.27-30.27v-402.42c0-31.327-26.8-30.27-26.8-30.27h15.2c16.72 0 30.27 13.55 30.27 30.27z" fill="#4278c3"/><path d="m304.62 41.34v381.77c0 8.4-6.81 15.2-15.2 15.2h-234.91c-8.4 0-15.2-6.8-15.2-15.2v-381.77c0-8.39 6.8-15.2 15.2-15.2h234.91c8.39 0 15.2 6.81 15.2 15.2z" fill="#c8effe"/><path d="m304.62 41.34v381.77c0 8.4-6.81 15.2-15.2 15.2h-26.82c8.4 0 15.2-6.8 15.2-15.2v-381.77c0-8.39-6.8-15.2-15.2-15.2h26.82c8.39 0 15.2 6.81 15.2 15.2z" fill="#99e6fc"/><path d="m264.127 131.158h-179.752c-3.296 0-5.968-2.672-5.968-5.968v-18.064c0-3.296 2.672-5.968 5.968-5.968h179.752c3.296 0 5.968 2.672 5.968 5.968v18.064c0 3.296-2.672 5.968-5.968 5.968z" fill="#7ca1b1"/><g><path d="m220.77 26.14v14.05c0 9.51-7.73 17.25-17.24 17.25h-63.14c-9.51 0-17.24-7.74-17.24-17.25v-14.05h-15v14.05c0 17.78 14.46 32.25 32.24 32.25h63.14c17.78 0 32.24-14.47 32.24-32.25v-14.05z" fill="#eaf6ff"/></g><g><path d="m127.729 188.148h-41.823c-4.142 0-7.5-3.358-7.5-7.5s3.358-7.5 7.5-7.5h41.823c4.142 0 7.5 3.358 7.5 7.5s-3.358 7.5-7.5 7.5z" fill="#7ca1b1"/></g><g><path d="m219.377 237.639h-133.471c-4.142 0-7.5-3.358-7.5-7.5s3.358-7.5 7.5-7.5h133.47c4.142 0 7.5 3.358 7.5 7.5s-3.357 7.5-7.499 7.5z" fill="#7ca1b1"/></g><g><path d="m206.116 287.129h-120.21c-4.142 0-7.5-3.358-7.5-7.5s3.358-7.5 7.5-7.5h120.209c4.142 0 7.5 3.358 7.5 7.5s-3.357 7.5-7.499 7.5z" fill="#7ca1b1"/></g><g><path d="m192.855 336.62h-106.949c-4.142 0-7.5-3.358-7.5-7.5s3.358-7.5 7.5-7.5h106.949c4.142 0 7.5 3.358 7.5 7.5s-3.358 7.5-7.5 7.5z" fill="#7ca1b1"/></g><g><path d="m127.729 386.111h-41.823c-4.142 0-7.5-3.358-7.5-7.5s3.358-7.5 7.5-7.5h41.823c4.142 0 7.5 3.358 7.5 7.5s-3.358 7.5-7.5 7.5z" fill="#7ca1b1"/></g><path d="m480.222 191.637-196.94-52.77c-5.578-1.495-11.311 1.816-12.806 7.393l-76.313 284.806c-1.495 5.578 1.816 11.311 7.393 12.806l196.94 52.77c5.578 1.495 11.311-1.816 12.806-7.393l76.313-284.806c1.495-5.578-1.815-11.311-7.393-12.806z" fill="#99e6fc"/><path d="m462.942 161.714-76.313 284.803c-1.493 5.573-7.228 8.892-12.801 7.399l-196.943-52.771c-5.573-1.493-8.89-7.237-7.396-12.811l76.313-284.803c1.496-5.583 7.237-8.89 12.811-7.396l196.943 52.771c5.572 1.493 8.882 7.225 7.386 12.808z" fill="#eaf6ff"/><path d="m462.94 161.71-76.31 284.81c-1.49 5.57-7.23 8.89-12.8 7.4l-31.56-8.46c5.57 1.49 11.32-1.82 12.81-7.4l76.31-284.8c1.49-5.55-1.78-11.26-7.3-12.78l31.46 8.43c5.58 1.49 8.89 7.22 7.39 12.8z" fill="#c8effe"/><circle cx="303.335" cy="323.106" fill="#46cc8d" r="73.713"/><path d="m397.838 233.335-131.46-35.225c-3.022-.81-4.815-3.916-4.005-6.937l12.375-46.186c.81-3.022 3.916-4.815 6.938-4.005l131.46 35.225c3.022.81 4.815 3.916 4.005 6.937l-12.375 46.186c-.81 3.021-3.916 4.814-6.938 4.005z" fill="#80b4fb"/><g><path d="m299.276 345.783c-2.592 0-5.113-1.345-6.502-3.751l-24.243-41.99c-2.071-3.587-.842-8.174 2.745-10.245 3.587-2.072 8.174-.842 10.245 2.745l20.493 35.495 66.234-38.24c3.587-2.072 8.174-.842 10.245 2.745s.842 8.174-2.745 10.245l-72.729 41.99c-1.181.682-2.471 1.006-3.743 1.006z" fill="#b0e7c9"/></g></g></svg></div>
        <h1>Mail Address Verifier</h1>
        <p>Автоматический анализ входящей электронной почты на предмет фишинга, мошенничества и вредоносных вложений с использованием AI</p>
    </div>

    <div class="container">
        <!-- What is this -->
        <div class="section">
            <h2>Что это такое?</h2>
            <p>Mail Address Verifier — это система автоматической проверки электронных писем. Она мониторит указанный почтовый ящик через IMAP, анализирует каждое входящее письмо и формирует детальный отчёт с оценкой уровня риска.</p>
            <p>Система использует многоуровневый анализ: технические проверки (DKIM, SPF, DMARC), OSINT-разведку отправителя, анализ домена и IP-адреса, проверку через VirusTotal, а также AI-анализ содержимого письма.</p>
        </div>

        <!-- Features -->
        <div class="section">
            <h2>Возможности</h2>
            <div class="features">
                <div class="feature">
                    <i class="fa-solid fa-envelope-circle-check"></i>
                    <h3>DKIM / SPF / DMARC</h3>
                    <p>Проверка подлинности отправителя и целостности письма</p>
                </div>
                <div class="feature">
                    <i class="fa-solid fa-magnifying-glass"></i>
                    <h3>OSINT-анализ</h3>
                    <p>Разведка по домену, IP-адресу, WHOIS и истории отправителя</p>
                </div>
                <div class="feature">
                    <i class="fa-solid fa-robot"></i>
                    <h3>AI-анализ</h3>
                    <p>Анализ содержимого через Perplexity, Claude или OpenAI</p>
                </div>
                <div class="feature">
                    <i class="fa-solid fa-virus-slash"></i>
                    <h3>VirusTotal</h3>
                    <p>Проверка ссылок и вложений на вирусы и малварь</p>
                </div>
                <div class="feature">
                    <i class="fa-solid fa-file-pdf"></i>
                    <h3>PDF-отчёты</h3>
                    <p>Детальный отчёт с результатами всех проверок</p>
                </div>
                <div class="feature">
                    <i class="fa-solid fa-bell"></i>
                    <h3>Email-уведомления</h3>
                    <p>Автоматическая отправка отчёта на указанные адреса</p>
                </div>
            </div>
        </div>

        <!-- How it works -->
        <div class="section">
            <h2>Как это работает?</h2>
            <div class="steps">
                <div class="step">
                    <h3>Пересылка письма</h3>
                    <p>Перешлите подозрительное письмо на адрес <b style="color:#fff;background:var(--blue);padding:2px 8px;border-radius:4px;">verify@2docs.info</b> <b>как вложение в формате .eml</b> (не простой forward!)</p>
                </div>
                <div class="step">
                    <h3>Автоматический анализ</h3>
                    <p>Система забирает письмо через IMAP, извлекает .eml-файл и запускает полный цикл проверок: заголовки, DKIM/SPF/DMARC, домен, IP, VirusTotal, AI-анализ</p>
                </div>
                <div class="step">
                    <h3>Формирование отчёта</h3>
                    <p>По результатам создаётся PDF-отчёт с оценкой риска (зелёный / жёлтый / красный) и отправляется на ваш email</p>
                </div>
                <div class="step">
                    <h3>Просмотр в панели</h3>
                    <p>Все результаты доступны в <a href="/admin" style="color:var(--blue)">Admin Panel</a> — история проверок, отчёты, статистика</p>
                </div>
            </div>
        </div>

        <!-- EML instructions -->
        <div class="section">
            <h2>Как сохранить письмо в формате .eml</h2>
            <div class="eml-box">
                <h3><i class="fa-solid fa-triangle-exclamation"></i> Важно: нужен именно .eml файл!</h3>
                <p>Система анализирует оригинальные заголовки письма (DKIM-подписи, SPF-записи, цепочку серверов). Обычная пересылка (forward) <b>теряет эту информацию</b>. Поэтому необходимо отправлять письмо именно как вложение в формате .eml.</p>
            </div>

            <table class="clients-table" style="margin-top: 20px;">
                <thead>
                    <tr>
                        <th>Почтовый клиент</th>
                        <th>Как сохранить/переслать как .eml</th>
                    </tr>
                </thead>
                <tbody>
                    <tr>
                        <td><b>Thunderbird</b></td>
                        <td>Правый клик на письме &rarr; <code>Forward As</code> &rarr; <code>Attachment</code>. Или: <code>File</code> &rarr; <code>Save As</code> &rarr; сохранить как .eml, затем прикрепить к новому письму.</td>
                    </tr>
                    <tr>
                        <td><b>Outlook (Desktop)</b></td>
                        <td>Создайте новое письмо, перетащите подозрительное письмо из списка прямо в окно нового письма — оно прикрепится как .eml файл.</td>
                    </tr>
                    <tr>
                        <td><b>Outlook (Web)</b></td>
                        <td>Откройте письмо &rarr; <code>...</code> (More actions) &rarr; <code>View message source</code>. Скопируйте текст, сохраните в файл с расширением .eml и прикрепите к новому письму.</td>
                    </tr>
                    <tr>
                        <td><b>Gmail (Web)</b></td>
                        <td>Откройте письмо &rarr; <code>&#8942;</code> (три точки справа) &rarr; <code>Download message</code> (Скачать сообщение). Файл .eml скачается на компьютер. Прикрепите его к новому письму.</td>
                    </tr>
                    <tr>
                        <td><b>Apple Mail</b></td>
                        <td>Выделите письмо &rarr; <code>File</code> &rarr; <code>Save As</code> &rarr; формат "Raw Message Source". Или перетащите письмо из списка на рабочий стол — создастся .eml файл.</td>
                    </tr>
                    <tr>
                        <td><b>Roundcube</b></td>
                        <td><code>More</code> &rarr; <code>Forward as attachment</code>. Письмо будет прикреплено как .eml к новому письму автоматически.</td>
                    </tr>
                    <tr>
                        <td><b>Любой клиент</b></td>
                        <td>Найдите опцию <code>Forward as Attachment</code> или <code>Save As .eml</code>. Если ничего нет — посмотрите исходный код письма (View Source), скопируйте текст целиком и сохраните в файл <code>message.eml</code>.</td>
                    </tr>
                </tbody>
            </table>
        </div>

        <!-- Risk levels -->
        <div class="section">
            <h2>Уровни риска</h2>
            <p>После анализа каждому письму присваивается числовой рейтинг (0-100) и цветовой уровень:</p>
            <div class="risk-legend">
                <div class="risk-item">
                    <div class="risk-dot g"></div>
                    <span><b>Зелёный (70-100)</b> — письмо безопасно</span>
                </div>
                <div class="risk-item">
                    <div class="risk-dot y"></div>
                    <span><b>Жёлтый (40-69)</b> — требует внимания</span>
                </div>
                <div class="risk-item">
                    <div class="risk-dot r"></div>
                    <span><b>Красный (0-39)</b> — высокий риск, вероятный фишинг</span>
                </div>
            </div>
        </div>

        <!-- What is checked -->
        <div class="section">
            <h2>Что проверяется</h2>
            <table class="clients-table">
                <thead>
                    <tr>
                        <th>Проверка</th>
                        <th>Описание</th>
                    </tr>
                </thead>
                <tbody>
                    <tr><td><b>DKIM</b></td><td>Цифровая подпись домена отправителя — подтверждает, что письмо не было изменено</td></tr>
                    <tr><td><b>SPF</b></td><td>Проверка, авторизован ли IP-адрес сервера для отправки писем от имени домена</td></tr>
                    <tr><td><b>DMARC</b></td><td>Политика домена по обработке писем, не прошедших DKIM/SPF</td></tr>
                    <tr><td><b>WHOIS домена</b></td><td>Возраст домена, регистратор, страна — новые домены часто используются для фишинга</td></tr>
                    <tr><td><b>IP-анализ</b></td><td>Геолокация, провайдер, проверка в чёрных списках (DNSBL)</td></tr>
                    <tr><td><b>VirusTotal</b></td><td>Проверка URL и доменов из письма по 70+ антивирусным движкам</td></tr>
                    <tr><td><b>OSINT</b></td><td>Поиск информации об отправителе в открытых источниках</td></tr>
                    <tr><td><b>AI-анализ</b></td><td>Анализ текста, намерений и контекста письма с помощью AI</td></tr>
                </tbody>
            </table>
        </div>

        <div class="footer">
            Mail Address Verifier &copy; 2024 &mdash; Internal security tool
        </div>
    </div>
</body>
</html>
'''

ADMIN_DASHBOARD_TEMPLATE = '''
<!DOCTYPE html>
<html>
<head>
    <title>Admin - Mail Verifier</title>
    <meta charset="utf-8">
    <meta name="viewport" content="width=device-width, initial-scale=1">
    <link rel="stylesheet" href="https://cdnjs.cloudflare.com/ajax/libs/font-awesome/6.4.0/css/all.min.css">
    <style>
        :root {
            --blue: #3498db; --green: #27ae60; --yellow: #f39c12;
            --red: #e74c3c; --gray: #95a5a6; --dark: #2c3e50;
            --bg: #f0f2f5; --card: #fff; --border: #e8ecf1;
        }
        * { margin: 0; padding: 0; box-sizing: border-box; }
        body { font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif; background: var(--bg); color: #333; }
        .container { max-width: 1200px; margin: 0 auto; padding: 16px; }

        /* Header */
        .header { display: flex; justify-content: space-between; align-items: center; margin-bottom: 20px; flex-wrap: wrap; gap: 10px; }
        .header h1 { font-size: 20px; color: var(--dark); }
        .header-links { display: flex; gap: 8px; }
        .header-link { padding: 8px 16px; color: #fff; text-decoration: none; border-radius: 6px; font-size: 13px; font-weight: 600; }
        .header-link-home { background: var(--gray); }
        .header-link-admin { background: var(--dark); }

        /* Tabs */
        .tabs { display: flex; gap: 0; margin-bottom: 20px; border-bottom: 2px solid var(--border); }
        .tab { padding: 10px 20px; font-size: 14px; font-weight: 600; cursor: pointer; color: #888; border-bottom: 2px solid transparent; margin-bottom: -2px; transition: all .2s; }
        .tab:hover { color: var(--dark); }
        .tab.active { color: var(--blue); border-bottom-color: var(--blue); }
        .tab-content { display: none; }
        .tab-content.active { display: block; }

        /* Stats */
        .stats { display: grid; grid-template-columns: repeat(4, 1fr); gap: 12px; margin-bottom: 20px; }
        .stat-card { background: var(--card); padding: 16px; border-radius: 10px; box-shadow: 0 1px 3px rgba(0,0,0,.08); }
        .stat-card h3 { color: #888; font-size: 12px; text-transform: uppercase; letter-spacing: .5px; margin-bottom: 6px; }
        .stat-card .value { font-size: 28px; font-weight: 700; color: var(--dark); }
        .risk-dots { display: flex; gap: 12px; margin-top: 8px; font-size: 14px; font-weight: 600; }
        .risk-dots .g { color: var(--green); } .risk-dots .y { color: var(--yellow); } .risk-dots .r { color: var(--red); }

        /* Desktop table */
        .table-wrap { background: var(--card); border-radius: 10px; box-shadow: 0 1px 3px rgba(0,0,0,.08); overflow-x: auto; }
        table { width: 100%; border-collapse: collapse; min-width: 700px; }
        th { background: var(--blue); color: #fff; padding: 12px 14px; text-align: left; font-size: 13px; font-weight: 600; white-space: nowrap; }
        td { padding: 10px 14px; border-bottom: 1px solid var(--border); font-size: 13px; vertical-align: middle; }
        tr:hover { background: #f8f9fb; }
        .td-from { max-width: 200px; overflow: hidden; text-overflow: ellipsis; white-space: nowrap; }
        .td-subj { max-width: 220px; overflow: hidden; text-overflow: ellipsis; white-space: nowrap; }

        /* Status badge */
        .badge { display: inline-block; padding: 3px 10px; border-radius: 10px; font-size: 11px; font-weight: 700; text-transform: uppercase; }
        .badge-pending { background: #ecf0f1; color: #7f8c8d; }
        .badge-processing { background: #d6eaf8; color: #2471a3; }
        .badge-completed { background: #d5f5e3; color: #1e8449; }
        .badge-failed { background: #fadbd8; color: #c0392b; }

        /* Action buttons */
        .actions { display: flex; gap: 4px; }
        .abtn { display: inline-flex; align-items: center; justify-content: center; width: 32px; height: 32px; border: none; border-radius: 6px; cursor: pointer; color: #fff; font-size: 13px; transition: opacity .15s; }
        .abtn:hover { opacity: .85; }
        .abtn-pdf { background: var(--green); }
        .abtn-re { background: var(--blue); }
        .abtn-del { background: var(--gray); }
        .abtn-off { background: #ecf0f1; color: #bdc3c7; cursor: default; pointer-events: none; }

        /* Mobile cards (hidden on desktop) */
        .cards { display: none; }
        .check-card { background: var(--card); border-radius: 10px; box-shadow: 0 1px 3px rgba(0,0,0,.08); padding: 14px; margin-bottom: 10px; }
        .card-top { display: flex; justify-content: space-between; align-items: flex-start; margin-bottom: 8px; }
        .card-from { font-weight: 600; font-size: 14px; color: var(--dark); word-break: break-all; }
        .card-subj { color: #666; font-size: 13px; margin-bottom: 8px; word-break: break-word; }
        .card-meta { display: flex; flex-wrap: wrap; gap: 8px; align-items: center; font-size: 12px; color: #888; margin-bottom: 10px; }
        .card-meta .score { font-weight: 700; color: var(--dark); font-size: 14px; }
        .card-actions { display: flex; gap: 6px; }
        .card-actions .abtn { width: 36px; height: 36px; font-size: 14px; }

        /* Admin tools */
        .admin-card { background: var(--card); padding: 24px; border-radius: 10px; box-shadow: 0 1px 3px rgba(0,0,0,.08); margin-bottom: 16px; }
        .admin-card h3 { font-size: 16px; color: var(--dark); margin-bottom: 12px; }
        .admin-card p { font-size: 13px; color: #666; margin-bottom: 12px; }
        .form-group { margin-bottom: 12px; }
        .form-group label { display: block; font-size: 13px; color: #666; font-weight: 600; margin-bottom: 6px; }
        .form-group input[type="text"], .form-group input[type="password"] { width: 100%; padding: 10px 12px; border: 1px solid var(--border); border-radius: 6px; font-size: 14px; }
        .form-group input:focus { outline: none; border-color: var(--blue); box-shadow: 0 0 0 3px rgba(52,152,219,.15); }
        .checkbox-group { display: flex; align-items: center; gap: 8px; }
        .checkbox-group input { width: auto; }
        .btn { padding: 10px 20px; border: none; border-radius: 6px; cursor: pointer; font-size: 14px; font-weight: 600; color: #fff; transition: opacity .15s; }
        .btn:hover { opacity: .85; }
        .btn-danger { background: var(--red); }
        .btn-success { background: var(--green); }
        .users-table { width: 100%; border-collapse: collapse; margin-top: 12px; min-width: auto; }
        .users-table th { background: var(--dark); }
        .users-table td { font-size: 13px; }

        /* Login */
        .login-wrap { max-width: 380px; margin: 80px auto; }
        .login-card { background: var(--card); padding: 30px; border-radius: 12px; box-shadow: 0 2px 8px rgba(0,0,0,.1); }
        .login-card h2 { font-size: 18px; color: var(--dark); margin-bottom: 20px; }
        .login-card label { display: block; font-size: 13px; color: #666; font-weight: 600; margin-bottom: 6px; }
        .login-card input { width: 100%; padding: 10px 12px; border: 1px solid var(--border); border-radius: 6px; font-size: 14px; margin-bottom: 16px; }
        .login-card input:focus { outline: none; border-color: var(--blue); box-shadow: 0 0 0 3px rgba(52,152,219,.15); }
        .login-btn { width: 100%; padding: 10px; background: var(--blue); color: #fff; border: none; border-radius: 6px; font-size: 14px; font-weight: 600; cursor: pointer; }
        .login-btn:hover { background: #2980b9; }

        .loading-msg { text-align: center; padding: 40px; color: #999; }

        /* Notification */
        .notif { position: fixed; top: 16px; right: 16px; padding: 12px 20px; color: #fff; border-radius: 8px; box-shadow: 0 4px 12px rgba(0,0,0,.2); z-index: 10000; animation: slideIn .3s ease-out; font-size: 14px; }
        @keyframes slideIn { from { transform: translateX(120%); opacity: 0; } to { transform: translateX(0); opacity: 1; } }
        @keyframes slideOut { from { opacity: 1; } to { transform: translateX(120%); opacity: 0; } }

        /* Responsive */
        @media (max-width: 768px) {
            .container { padding: 10px; }
            .header h1 { font-size: 16px; }
            .stats { grid-template-columns: repeat(2, 1fr); gap: 8px; }
            .stat-card { padding: 12px; }
            .stat-card .value { font-size: 22px; }
            .table-wrap { display: none; }
            .cards { display: block; }
            .tab { padding: 8px 14px; font-size: 13px; }
        }
        @media (max-width: 400px) {
            .stats { grid-template-columns: 1fr 1fr; }
            .stat-card .value { font-size: 20px; }
        }
    </style>
</head>
<body>
    <div class="container">
        <!-- Login -->
        {% if not session.get('admin_authenticated') %}
        <div id="auth-section" class="login-wrap">
            <div class="login-card">
                <h2><i class="fa-solid fa-shield-halved" style="color:var(--blue)"></i> Mail Verifier</h2>
                <form method="POST" action="/admin/login">
                    <label>Password</label>
                    <input type="password" name="password" id="admin-password" placeholder="Enter admin password" autofocus>
                    {% if login_error %}
                    <div style="color:var(--red);font-size:13px;margin-bottom:10px;">{{ login_error }}</div>
                    {% endif %}
                    <button type="submit" class="login-btn">Login</button>
                </form>
            </div>
        </div>
        {% endif %}

        <!-- Main -->
        {% if session.get('admin_authenticated') %}
        <div id="main-content">

            <div class="header">
                <h1><i class="fa-solid fa-shield-halved" style="color:var(--blue)"></i> Mail Verifier</h1>
                <div class="header-links">
                    <a href="/" class="header-link header-link-home"><i class="fa-solid fa-house"></i> Info</a>
                </div>
            </div>

            <!-- Tabs -->
            <div class="tabs">
                <div class="tab active" data-tab="checks"><i class="fa-solid fa-envelope-open-text"></i> Checks</div>
                <div class="tab" data-tab="tools"><i class="fa-solid fa-gear"></i> Admin Tools</div>
            </div>

            <!-- Tab: Checks -->
            <div class="tab-content active" id="tab-checks">
                <div class="stats">
                    <div class="stat-card">
                        <h3>Total</h3>
                        <div class="value" id="total-checks">{{ stats.get('total', '-') }}</div>
                    </div>
                    <div class="stat-card">
                        <h3>Completed</h3>
                        <div class="value" id="completed-checks">{{ stats.get('completed', '-') }}</div>
                    </div>
                    <div class="stat-card">
                        <h3>Processing</h3>
                        <div class="value" id="processing-checks">{{ stats.get('processing', '-') }}</div>
                    </div>
                    <div class="stat-card">
                        <h3>Risk</h3>
                        <div class="risk-dots">
                            <span class="g"><i class="fa-solid fa-circle" style="font-size:10px"></i> <span id="green-count">{{ stats.get('green', 0) }}</span></span>
                            <span class="y"><i class="fa-solid fa-circle" style="font-size:10px"></i> <span id="yellow-count">{{ stats.get('yellow', 0) }}</span></span>
                            <span class="r"><i class="fa-solid fa-circle" style="font-size:10px"></i> <span id="red-count">{{ stats.get('red', 0) }}</span></span>
                        </div>
                    </div>
                </div>

                <!-- Desktop table -->
                <div class="table-wrap">
                    <table>
                        <thead>
                            <tr>
                                <th>Date</th>
                                <th>From</th>
                                <th>Subject</th>
                                <th>Status</th>
                                <th>Risk</th>
                                <th>Score</th>
                                <th>Actions</th>
                            </tr>
                        </thead>
                        <tbody id="checks-tbody">
                            {% if checks %}
                            {% for c in checks %}
                            {% set risk_icon = {'green': '<i class="fa-solid fa-circle" style="color:var(--green);font-size:12px"></i>', 'yellow': '<i class="fa-solid fa-circle" style="color:var(--yellow);font-size:12px"></i>', 'red': '<i class="fa-solid fa-circle" style="color:var(--red);font-size:12px"></i>'} %}
                            <tr>
                                <td style="white-space:nowrap">{{ c.created_at }}</td>
                                <td class="td-from" title="{{ c.from_address }}">{{ c.from_address }}</td>
                                <td class="td-subj" title="{{ c.subject }}">{{ c.subject }}</td>
                                <td><span class="badge badge-{{ c.status }}">{{ c.status }}</span></td>
                                <td>{{ risk_icon.get(c.risk_level, '-') | safe }}</td>
                                <td><b>{{ c.overall_score }}</b></td>
                                <td><div class="actions">
                                    <a class="abtn {{ 'abtn-pdf' if c.has_report else 'abtn-off' }}" href="{{ '/api/check/' ~ c.id ~ '/report' if c.has_report else '#' }}" target="_blank" title="PDF"><i class="fa-solid fa-file-pdf"></i></a>
                                    <form method="POST" action="/admin/recheck/{{ c.id }}" style="display:inline">
                                        <button type="submit" class="abtn abtn-re" title="Recheck"><i class="fa-solid fa-rotate-right"></i></button>
                                    </form>
                                    <form method="POST" action="/admin/delete/{{ c.id }}" style="display:inline" onsubmit="return confirm('Delete this check?')">
                                        <button type="submit" class="abtn abtn-del" title="Delete"><i class="fa-solid fa-trash-can"></i></button>
                                    </form>
                                </div></td>
                            </tr>
                            {% endfor %}
                            {% else %}
                            <tr><td colspan="7" class="loading-msg">No checks yet</td></tr>
                            {% endif %}
                        </tbody>
                    </table>
                </div>

                <!-- Mobile cards -->
                <div class="cards" id="checks-cards">
                    {% if checks %}
                    {% set risk_icon = {'green': '<i class="fa-solid fa-circle" style="color:var(--green);font-size:12px"></i>', 'yellow': '<i class="fa-solid fa-circle" style="color:var(--yellow);font-size:12px"></i>', 'red': '<i class="fa-solid fa-circle" style="color:var(--red);font-size:12px"></i>'} %}
                    {% for c in checks %}
                    <div class="check-card">
                        <div class="card-top">
                            <div class="card-from">{{ c.from_address }}</div>
                            {{ risk_icon.get(c.risk_level, '') | safe }}
                        </div>
                        <div class="card-subj">{{ c.subject }}</div>
                        <div class="card-meta">
                            <span>{{ c.created_at }}</span>
                            <span class="badge badge-{{ c.status }}">{{ c.status }}</span>
                            <span class="score">{{ c.overall_score }}</span>
                        </div>
                        <div class="card-actions">
                            <a class="abtn {{ 'abtn-pdf' if c.has_report else 'abtn-off' }}" href="{{ '/api/check/' ~ c.id ~ '/report' if c.has_report else '#' }}" target="_blank" title="PDF"><i class="fa-solid fa-file-pdf"></i></a>
                            <form method="POST" action="/admin/recheck/{{ c.id }}" style="display:inline">
                                <button type="submit" class="abtn abtn-re" title="Recheck"><i class="fa-solid fa-rotate-right"></i></button>
                            </form>
                            <form method="POST" action="/admin/delete/{{ c.id }}" style="display:inline" onsubmit="return confirm('Delete?')">
                                <button type="submit" class="abtn abtn-del" title="Delete"><i class="fa-solid fa-trash-can"></i></button>
                            </form>
                        </div>
                    </div>
                    {% endfor %}
                    {% else %}
                    <div class="loading-msg">No checks yet</div>
                    {% endif %}
                </div>
            </div>

            <!-- Tab: Admin Tools -->
            <div class="tab-content" id="tab-tools">
                <div class="admin-card">
                    <h3><i class="fa-solid fa-trash-can" style="color:var(--red)"></i> Clear Database</h3>
                    <p>Удалить ВСЕ проверки, результаты и файлы. Действие необратимо!</p>
                    <form method="POST" action="/admin/clear-database" onsubmit="return confirm('УДАЛИТЬ ВСЕ ДАННЫЕ? Действие необратимо!')">
                        <button type="submit" class="btn btn-danger">Clear All Data</button>
                    </form>
                </div>

                <div class="admin-card">
                    <h3><i class="fa-solid fa-user-plus" style="color:var(--green)"></i> Create User</h3>
                    <form method="POST" action="/admin/create-user">
                        <div class="form-group">
                            <label>Username:</label>
                            <input type="text" name="username" placeholder="Enter username" required>
                        </div>
                        <div class="form-group">
                            <label>Password:</label>
                            <input type="password" name="password" placeholder="Enter password" required>
                        </div>
                        <div class="form-group checkbox-group">
                            <input type="checkbox" name="is_admin" id="new-is-admin" value="1">
                            <label for="new-is-admin">Admin privileges</label>
                        </div>
                        <button type="submit" class="btn btn-success">Create User</button>
                    </form>
                </div>

                <div class="admin-card">
                    <h3><i class="fa-solid fa-users" style="color:var(--blue)"></i> Users</h3>
                    <div class="table-wrap">
                        <table class="users-table">
                            <thead>
                                <tr>
                                    <th>ID</th>
                                    <th>Username</th>
                                    <th>Admin</th>
                                    <th>Created</th>
                                </tr>
                            </thead>
                            <tbody>
                                {% if users %}
                                {% for u in users %}
                                <tr>
                                    <td>{{ u.id }}</td>
                                    <td>{{ u.username }}</td>
                                    <td>{% if u.is_admin %}<i class="fa-solid fa-check" style="color:var(--green)"></i>{% else %}-{% endif %}</td>
                                    <td>{{ u.created_at }}</td>
                                </tr>
                                {% endfor %}
                                {% else %}
                                <tr><td colspan="4" class="loading-msg">No users yet</td></tr>
                                {% endif %}
                            </tbody>
                        </table>
                    </div>
                </div>
            </div>
        </div>
        {% endif %}
    </div>

    <script>
        // Tab switching
        document.querySelectorAll('.tab').forEach(tab => {
            tab.addEventListener('click', () => {
                document.querySelectorAll('.tab').forEach(t => t.classList.remove('active'));
                document.querySelectorAll('.tab-content').forEach(c => c.classList.remove('active'));
                tab.classList.add('active');
                document.getElementById('tab-' + tab.dataset.tab).classList.add('active');
            });
        });

        {% if session.get('admin_authenticated') %}
        // Auto-refresh every 30s
        setInterval(() => { window.location.reload(); }, 30000);
        {% endif %}
    </script>
</body>
</html>
'''
