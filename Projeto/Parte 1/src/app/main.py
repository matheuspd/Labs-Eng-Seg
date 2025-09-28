from flask import Flask, request, render_template, redirect, url_for, session, jsonify, flash
from flask_sqlalchemy import SQLAlchemy
from flask_cors import CORS
import os
import psycopg2
from models import db, User, Product, Order, OrderItem

app = Flask(__name__)

# Intentionally weak secret key for session management (vulnerability)
app.secret_key = 'weak_secret_key_123'

# CORS configuration - allowing all origins (vulnerability)
CORS(app, origins="*", supports_credentials=True)

# Database configuration
DATABASE_URL = os.environ.get('DATABASE_URL', 'postgresql://vulnuser:vulnpass@localhost:5432/vulndb')
app.config['SQLALCHEMY_DATABASE_URI'] = DATABASE_URL
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

# Initialize database
db.init_app(app)

# Vulnerable direct database connection for SQL injection demonstrations
def get_db_connection():
    return psycopg2.connect(DATABASE_URL)

# Helper function to check if user is logged in (intentionally weak)
def is_logged_in():
    return 'user_id' in session

def get_current_user():
    if is_logged_in():
        # Vulnerable SQL query - direct string interpolation
        conn = get_db_connection()
        cursor = conn.cursor()
        query = f"SELECT * FROM users WHERE id = {session['user_id']}"
        cursor.execute(query)
        user_data = cursor.fetchone()
        cursor.close()
        conn.close()
        return user_data
    return None

# Routes
@app.route('/')
def index():
    if is_logged_in():
        return redirect(url_for('dashboard'))
    return redirect(url_for('login'))

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        
        # Vulnerable SQL injection in login
        conn = get_db_connection()
        cursor = conn.cursor()
        
        # Intentionally vulnerable query - allows SQL injection
        query = f"SELECT * FROM users WHERE username = '{username}' AND password = '{password}'"
        
        try:
            cursor.execute(query)
            user = cursor.fetchone()
            
            if user:
                # Weak session management - predictable session IDs
                session['user_id'] = user[0]
                session['username'] = user[1]
                session['role'] = user[4]
                flash(f'Welcome {user[1]}!', 'success')
                return redirect(url_for('dashboard'))
            else:
                # Detailed error message revealing information (vulnerability)
                flash(f'Login failed for user: {username}. Invalid credentials.', 'error')
        except Exception as e:
            # Exposing database errors (vulnerability)
            flash(f'Database error: {str(e)}', 'error')
        finally:
            cursor.close()
            conn.close()
    
    return render_template('login.html')

@app.route('/logout')
def logout():
    session.clear()
    flash('You have been logged out.', 'info')
    return redirect(url_for('login'))

@app.route('/dashboard')
def dashboard():
    if not is_logged_in():
        return redirect(url_for('login'))
    
    user = get_current_user()
    if not user:
        return redirect(url_for('login'))
    
    user_id = user[0]
    role = user[4]  # role is at index 4

    conn = get_db_connection()
    cursor = conn.cursor()

    users_count = None
    products_count = None
    orders_count = None
    customers_count = None

    if role == 'admin':
        # Admin vê tudo
        cursor.execute("SELECT COUNT(*) FROM users")
        users_count = cursor.fetchone()[0]

        cursor.execute("SELECT COUNT(*) FROM products")
        products_count = cursor.fetchone()[0]

        cursor.execute("SELECT COUNT(*) FROM orders")
        orders_count = cursor.fetchone()[0]

        cursor.execute("SELECT COUNT(*) FROM users WHERE role = 'customer'")
        customers_count = cursor.fetchone()[0]

    elif role == 'employee':
        # Employee vê produtos, pedidos dele e clientes
        cursor.execute("SELECT COUNT(*) FROM products")
        products_count = cursor.fetchone()[0]

        cursor.execute("SELECT COUNT(*) FROM orders WHERE employee_id = %s", (user_id,))
        orders_count = cursor.fetchone()[0]

        cursor.execute("SELECT COUNT(*) FROM users WHERE role = 'customer'")
        customers_count = cursor.fetchone()[0]

    elif role == 'customer':
        # Customer vê apenas pedidos dele
        cursor.execute("SELECT COUNT(*) FROM orders WHERE customer_id = %s", (user_id,))
        orders_count = cursor.fetchone()[0]

    cursor.close()
    conn.close()
    
    return render_template(
        'dashboard.html',
        user=user,
        role=role,
        users_count=users_count,
        products_count=products_count,
        orders_count=orders_count,
        customers_count=customers_count
    )

# Vulnerable route - no proper access control
@app.route('/admin')
def admin_panel():
    # Missing proper authorization check - any logged-in user can access
    if not is_logged_in():
        return redirect(url_for('login'))
    
    # Get all users (vulnerable - no access control)
    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute("SELECT * FROM users")
    users = cursor.fetchall()
    cursor.close()
    conn.close()
    
    return render_template('admin.html', users=users)

# Vulnerable IDOR - Insecure Direct Object Reference
@app.route('/user/<int:user_id>')
def view_user(user_id):
    if not is_logged_in():
        return redirect(url_for('login'))
    
    # No authorization check - any user can view any other user's profile
    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute(f"SELECT * FROM users WHERE id = {user_id}")
    user = cursor.fetchone()
    cursor.close()
    conn.close()
    
    if user:
        return render_template('user_profile.html', profile_user=user)
    else:
        flash('User not found', 'error')
        return redirect(url_for('dashboard'))

# Products management with SQL injection vulnerability
@app.route('/products')
def products():
    if not is_logged_in():
        return redirect(url_for('login'))
    
    search = request.args.get('search', '')
    
    conn = get_db_connection()
    cursor = conn.cursor()
    
    if search:
        # Vulnerable search query - SQL injection possible
        query = f"SELECT * FROM products WHERE name LIKE '%{search}%' OR description LIKE '%{search}%'"
    else:
        query = "SELECT * FROM products"
    
    try:
        cursor.execute(query)
        products = cursor.fetchall()
    except Exception as e:
        flash(f'Search error: {str(e)}', 'error')
        products = []
    finally:
        cursor.close()
        conn.close()
    
    return render_template('products.html', products=products, search=search)

# Orders with IDOR vulnerability
@app.route('/orders')
def orders():
    if not is_logged_in():
        return redirect(url_for('login'))
    
    user = get_current_user()
    role = user[4]

    orders = []
    products = []
    
    conn = get_db_connection()
    cursor = conn.cursor()
    
    # Weak access control - customers should only see their orders
    if role == 'customer':
        # But this can be bypassed by manipulating the URL
        cursor.execute("SELECT * FROM orders WHERE customer_id = %s", (user[0],))
        orders = cursor.fetchall()

        cursor.execute("SELECT id, name, description, price FROM products")
        products = cursor.fetchall()
    elif role == 'employee':
        cursor.execute(f"SELECT * FROM orders WHERE employee_id = {user[0]}")
        orders = cursor.fetchall()
        cursor.execute("SELECT id, name, description, price FROM products")
        products = cursor.fetchall()
    else:
        cursor.execute("SELECT * FROM orders")
        orders = cursor.fetchall()
        cursor.execute("SELECT id, name, description, price FROM products")
        products = cursor.fetchall()
    

    cursor.close()
    conn.close()

    return render_template('orders.html', orders=orders, products=products, role=role)

# Vulnerable order detail view - IDOR
@app.route('/order/<int:order_id>')
def order_detail(order_id):
    if not is_logged_in():
        return redirect(url_for('login'))
    
    conn = get_db_connection()
    cursor = conn.cursor()

    # Buscar pedido
    cursor.execute(f"SELECT * FROM orders WHERE id = {order_id}")
    order = cursor.fetchone()

    # Buscar itens do pedido
    order_items = []
    if order:
        cursor.execute(f"""
            SELECT p.name, oi.quantity, p.price
            FROM order_items oi
            JOIN products p ON p.id = oi.product_id
            WHERE oi.order_id = {order_id}
        """)
        order_items = cursor.fetchall()  # [(name, quantity, price), ...]
    
    cursor.close()
    conn.close()

    if order:
        return render_template('order_detail.html', order=order, order_items=order_items)
    else:
        flash('Order not found', 'error')
        return redirect(url_for('orders'))


@app.route('/api/create_order', methods=['POST'])
def api_create_order():
    if not is_logged_in() or session.get('role') != 'customer':
        return jsonify({'error': 'Somente clientes podem criar pedidos'}), 403

    items = request.json.get('items')  # espera: [{"product_id": 1, "quantity": 2}, ...]
    if not items or not isinstance(items, list):
        return jsonify({'error': 'Lista de itens inválida'}), 400

    customer_id = session['user_id']
    conn = get_db_connection()
    cursor = conn.cursor()

    try:
        total_amount = 0
        item_details = []

        # Buscar preços e calcular total
        for item in items:
            product_id = item.get('product_id')
            quantity = int(item.get('quantity', 1))

            cursor.execute(f"SELECT price FROM products WHERE id = {product_id}")
            product = cursor.fetchone()
            if not product:
                return jsonify({'error': f'Produto {product_id} não encontrado'}), 404

            price = float(product[0])
            total_amount += price * quantity
            item_details.append((product_id, quantity, price))

        # Inserir pedido
        cursor.execute(f"""
            INSERT INTO orders (customer_id, total_amount, status)
            VALUES ({customer_id}, {total_amount}, 'pending')
            RETURNING id
        """)
        order_id = cursor.fetchone()[0]

        # Inserir itens do pedido
        for product_id, quantity, price in item_details:
            cursor.execute(f"""
                INSERT INTO order_items (order_id, product_id, quantity, unit_price)
                VALUES ({order_id}, {product_id}, {quantity}, {price})
            """)

        conn.commit()
        return jsonify({'success': True, 'order_id': order_id})

    except Exception as e:
        conn.rollback()
        return jsonify({'error': str(e)}), 500
    finally:
        cursor.close()
        conn.close()


# API endpoint para adicionar produto (vulnerável a SQLi e sem CSRF)
@app.route('/api/add_product', methods=['POST'])
def api_add_product():
    if not is_logged_in():
        return jsonify({'error': 'Not authenticated'}), 401
    
    name = request.json.get('name')
    description = request.json.get('description')
    price = request.json.get('price')
    stock = request.json.get('stock')

    created_by = session['user_id']  # quem criou
    
    conn = get_db_connection()
    cursor = conn.cursor()

    # Vulnerável: interpolação direta
    query = f"""
        INSERT INTO products (name, description, price, stock_quantity, created_by)
        VALUES ('{name}', '{description}', {price}, {stock}, {created_by})
    """
    try:
        cursor.execute(query)
        conn.commit()
        return jsonify({'success': True})
    except Exception as e:
        conn.rollback()
        return jsonify({'error': str(e)}), 500
    finally:
        cursor.close()
        conn.close()


# API endpoint with no CSRF protection
@app.route('/api/update_product', methods=['POST'])
def api_update_product():
    if not is_logged_in():
        return jsonify({'error': 'Not authenticated'}), 401
    
    # No CSRF token validation
    product_id = request.json.get('id')
    name = request.json.get('name')
    price = request.json.get('price')
    
    # Vulnerable SQL update
    conn = get_db_connection()
    cursor = conn.cursor()
    query = f"UPDATE products SET name = '{name}', price = {price} WHERE id = {product_id}"
    
    try:
        cursor.execute(query)
        conn.commit()
        return jsonify({'success': True})
    except Exception as e:
        return jsonify({'error': str(e)}), 500
    finally:
        cursor.close()
        conn.close()

# File upload vulnerability (if needed later)
@app.route('/upload', methods=['GET', 'POST'])
def upload_file():
    if not is_logged_in():
        return redirect(url_for('login'))
    
    if request.method == 'POST':
        # Vulnerable file upload - no validation
        file = request.files.get('file')
        if file:
            # Dangerous - saves file with original name, no validation
            filename = file.filename
            file.save(f'/tmp/{filename}')
            flash(f'File {filename} uploaded successfully!', 'success')
    
    return render_template('upload.html')


# Additional vulnerable API endpoints
@app.route('/api/add_user', methods=['POST'])
def api_add_user():
    if not is_logged_in():
        return jsonify({'error': 'Not authenticated'}), 401
    
    # No role-based access control - any user can add users
    username = request.form.get('username')
    password = request.form.get('password')
    email = request.form.get('email')
    role = request.form.get('role')
    
    # Vulnerable SQL insertion
    conn = get_db_connection()
    cursor = conn.cursor()
    query = f"INSERT INTO users (username, password, email, role) VALUES ('{username}', '{password}', '{email}', '{role}')"
    
    try:
        cursor.execute(query)
        conn.commit()
        return jsonify({'success': True, 'message': 'User added successfully'})
    except Exception as e:
        return jsonify({'error': str(e)}), 500
    finally:
        cursor.close()
        conn.close()

@app.route('/api/update_user', methods=['POST'])
def api_update_user():
    if not is_logged_in():
        return jsonify({'error': 'Not authenticated'}), 401
    
    # No CSRF protection, no proper authorization
    data = request.get_json()
    user_id = data.get('id')
    username = data.get('username')
    email = data.get('email')
    role = data.get('role')
    
    # Vulnerable SQL update
    conn = get_db_connection()
    cursor = conn.cursor()
    query = f"UPDATE users SET username = '{username}', email = '{email}', role = '{role}' WHERE id = {user_id}"
    
    try:
        cursor.execute(query)
        conn.commit()
        return jsonify({'success': True})
    except Exception as e:
        return jsonify({'error': str(e)}), 500
    finally:
        cursor.close()
        conn.close()

@app.route('/api/delete_user', methods=['POST'])
def api_delete_user():
    if not is_logged_in():
        return jsonify({'error': 'Not authenticated'}), 401
    
    # No CSRF protection, any user can delete others
    data = request.get_json()
    user_id = data.get('id')
    
    # Vulnerable deletion
    conn = get_db_connection()
    cursor = conn.cursor()
    query = f"DELETE FROM users WHERE id = {user_id}"
    
    try:
        cursor.execute(query)
        conn.commit()
        return jsonify({'success': True})
    except Exception as e:
        return jsonify({'error': str(e)}), 500
    finally:
        cursor.close()
        conn.close()

# Atualiza status do pedido (substitui/atualiza a versão existente)
@app.route('/api/update_order_status', methods=['POST'])
def api_update_order_status():
    if not is_logged_in():
        return jsonify({'error': 'Not authenticated'}), 401

    data = request.get_json() or {}
    order_id = data.get('order_id')
    status = data.get('status')

    if not order_id or not status:
        return jsonify({'error': 'order_id and status required'}), 400

    # Permitir somente valores válidos (ainda vulnerável por usar SQL interpolado)
    valid_statuses = ('pending', 'processing', 'completed', 'cancelled')
    if status not in valid_statuses:
        return jsonify({'error': f'Invalid status: {status}'}), 400

    conn = get_db_connection()
    cursor = conn.cursor()
    try:
        # (vulnerável) interpolação direta
        query = f"UPDATE orders SET status = '{status}' WHERE id = {order_id}"
        cursor.execute(query)
        conn.commit()
        return jsonify({'success': True, 'order_id': order_id, 'status': status})
    except Exception as e:
        conn.rollback()
        return jsonify({'error': str(e)}), 500
    finally:
        cursor.close()
        conn.close()


# Atribuir funcionário ao pedido
@app.route('/api/assign_employee', methods=['POST'])
def api_assign_employee():
    if not is_logged_in():
        return jsonify({'error': 'Not authenticated'}), 401

    data = request.get_json() or {}
    order_id = data.get('order_id')
    employee_id = data.get('employee_id')

    if not order_id or not employee_id:
        return jsonify({'error': 'order_id and employee_id required'}), 400

    conn = get_db_connection()
    cursor = conn.cursor()
    try:
        # Opcional: verificar se o employee_id existe (pequeno check)
        cursor.execute(f"SELECT id FROM users WHERE id = {employee_id} AND role = 'employee'")
        emp = cursor.fetchone()
        if not emp:
            # Mantemos a vulnerabilidade, mas retornamos mensagem clara
            return jsonify({'error': f'Employee {employee_id} not found'}), 404

        # (vulnerável) interpolação direta
        query = f"UPDATE orders SET employee_id = {employee_id} WHERE id = {order_id}"
        cursor.execute(query)
        conn.commit()
        return jsonify({'success': True, 'order_id': order_id, 'employee_id': employee_id})
    except Exception as e:
        conn.rollback()
        return jsonify({'error': str(e)}), 500
    finally:
        cursor.close()
        conn.close()


# Cancelar pedido (marca como 'cancelled')
@app.route('/api/cancel_order', methods=['POST'])
def api_cancel_order():
    if not is_logged_in():
        return jsonify({'error': 'Not authenticated'}), 401

    data = request.get_json() or {}
    order_id = data.get('order_id')

    if not order_id:
        return jsonify({'error': 'order_id required'}), 400

    conn = get_db_connection()
    cursor = conn.cursor()
    try:
        # (vulnerável) interpolação direta
        # opcionalmente pegamos o pedido atual para retornar info
        cursor.execute(f"SELECT status FROM orders WHERE id = {order_id}")
        existing = cursor.fetchone()
        if not existing:
            return jsonify({'error': 'Order not found'}), 404

        cursor.execute(f"UPDATE orders SET status = 'cancelled' WHERE id = {order_id}")
        conn.commit()
        return jsonify({'success': True, 'order_id': order_id, 'previous_status': existing[0], 'new_status': 'cancelled'})
    except Exception as e:
        conn.rollback()
        return jsonify({'error': str(e)}), 500
    finally:
        cursor.close()
        conn.close()


@app.route('/api/reset_password', methods=['POST'])
def api_reset_password():
    if not is_logged_in():
        return jsonify({'error': 'Not authenticated'}), 401
    
    # Extremely vulnerable - any user can reset any password
    data = request.get_json()
    user_id = data.get('user_id')
    new_password = data.get('new_password')
    
    # No validation, no authorization check
    conn = get_db_connection()
    cursor = conn.cursor()
    query = f"UPDATE users SET password = '{new_password}' WHERE id = {user_id}"
    
    try:
        cursor.execute(query)
        conn.commit()
        return jsonify({'success': True, 'message': 'Password reset successfully'})
    except Exception as e:
        return jsonify({'error': str(e)}), 500
    finally:
        cursor.close()
        conn.close()

# Vulnerable information disclosure endpoint
@app.route('/api/system_info')
def api_system_info():
    # No authentication required - exposes sensitive system information
    import platform
    import sys
    
    system_info = {
        'python_version': sys.version,
        'platform': platform.platform(),
        'database_url': DATABASE_URL,  # Exposing database credentials
        'secret_key': app.secret_key,  # Exposing secret key
        'debug_mode': app.debug,
        'users_count': 'SELECT COUNT(*) FROM users',  # Raw SQL exposed
        'session_data': dict(session)  # Exposing session data
    }
    
    return jsonify(system_info)

# Vulnerable debug endpoint
@app.route('/debug')
def debug_info():
    # Dangerous debug endpoint accessible in production
    if not is_logged_in():
        return redirect(url_for('login'))
    
    debug_data = {
        'session': dict(session),
        'request_headers': dict(request.headers),
        'environment_vars': dict(os.environ),
        'database_url': DATABASE_URL,
        'secret_key': app.secret_key
    }
    
    return render_template('debug.html', debug_data=debug_data)

# Vulnerable SQL injection endpoint for testing
@app.route('/api/search_users')
def api_search_users():
    if not is_logged_in():
        return jsonify({'error': 'Not authenticated'}), 401
    
    search_term = request.args.get('q', '')
    
    # Extremely vulnerable SQL injection
    conn = get_db_connection()
    cursor = conn.cursor()
    query = f"SELECT id, username, email, role FROM users WHERE username LIKE '%{search_term}%' OR email LIKE '%{search_term}%'"
    
    try:
        cursor.execute(query)
        users = cursor.fetchall()
        
        # Convert to list of dictionaries
        result = []
        for user in users:
            result.append({
                'id': user[0],
                'username': user[1],
                'email': user[2],
                'role': user[3]
            })
        
        return jsonify({'users': result, 'query': query})  # Exposing the actual query
    except Exception as e:
        return jsonify({'error': str(e), 'query': query}), 500  # Exposing query in error
    finally:
        cursor.close()
        conn.close()

# Vulnerable session management
@app.route('/api/get_session')
def api_get_session():
    # Exposes session data without proper authorization
    return jsonify({
        'session_id': request.cookies.get('session'),
        'session_data': dict(session),
        'user_agent': request.headers.get('User-Agent'),
        'ip_address': request.remote_addr
    })

# Vulnerable file operations
@app.route('/api/read_file')
def api_read_file():
    if not is_logged_in():
        return jsonify({'error': 'Not authenticated'}), 401
    
    # Directory traversal vulnerability
    filename = request.args.get('file', '')
    
    try:
        # Dangerous - allows reading any file on the system
        with open(filename, 'r') as f:
            content = f.read()
        return jsonify({'content': content, 'file': filename})
    except Exception as e:
        return jsonify({'error': str(e), 'file': filename}), 500

# Vulnerable command execution (extremely dangerous)
@app.route('/api/execute_command')
def api_execute_command():
    if not is_logged_in():
        return jsonify({'error': 'Not authenticated'}), 401
    
    # Remote code execution vulnerability
    command = request.args.get('cmd', '')
    
    if command:
        try:
            import subprocess
            result = subprocess.run(command, shell=True, capture_output=True, text=True)
            return jsonify({
                'command': command,
                'stdout': result.stdout,
                'stderr': result.stderr,
                'returncode': result.returncode
            })
        except Exception as e:
            return jsonify({'error': str(e), 'command': command}), 500
    
    return jsonify({'error': 'No command provided'})

# Add error handlers that expose sensitive information
@app.errorhandler(404)
def not_found_error(error):
    return render_template('error.html', 
                         error_code=404, 
                         error_message="Page not found",
                         debug_info={
                             'url': request.url,
                             'method': request.method,
                             'headers': dict(request.headers),
                             'session': dict(session)
                         }), 404

@app.errorhandler(500)
def internal_error(error):
    return render_template('error.html', 
                         error_code=500, 
                         error_message=str(error),
                         debug_info={
                             'url': request.url,
                             'method': request.method,
                             'headers': dict(request.headers),
                             'session': dict(session),
                             'database_url': DATABASE_URL
                         }), 500

if __name__ == '__main__':
    # Running in debug mode (vulnerability in production)
    app.run(host='0.0.0.0', port=5000, debug=True)