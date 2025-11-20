-- Create tables
CREATE TABLE IF NOT EXISTS users (
    id SERIAL PRIMARY KEY,
    username VARCHAR(50) UNIQUE NOT NULL,
    password VARCHAR(255) NOT NULL,
    email VARCHAR(100) UNIQUE NOT NULL,
    role VARCHAR(20) NOT NULL CHECK (role IN ('admin', 'employee', 'customer')),
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE IF NOT EXISTS products (
    id SERIAL PRIMARY KEY,
    name VARCHAR(100) NOT NULL,
    description TEXT,
    price DECIMAL(10, 2) NOT NULL,
    stock_quantity INTEGER DEFAULT 0,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    created_by INTEGER REFERENCES users(id)
);

CREATE TABLE IF NOT EXISTS orders (
    id SERIAL PRIMARY KEY,
    customer_id INTEGER REFERENCES users(id),
    employee_id INTEGER REFERENCES users(id),
    total_amount DECIMAL(10, 2) NOT NULL,
    status VARCHAR(20) DEFAULT 'pending' CHECK (status IN ('pending', 'processing', 'completed', 'cancelled')),
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE IF NOT EXISTS order_items (
    id SERIAL PRIMARY KEY,
    order_id INTEGER REFERENCES orders(id),
    product_id INTEGER REFERENCES products(id),
    quantity INTEGER NOT NULL,
    unit_price DECIMAL(10, 2) NOT NULL
);

-- Insert sample data
-- Users (passwords are intentionally weak and stored in plain text for vulnerability demonstration)
INSERT INTO users (username, password, email, role) VALUES
('admin', 'admin123', 'admin@vulnshop.com', 'admin'),
('employee1', 'emp123', 'emp1@vulnshop.com', 'employee'),
('employee2', 'password', 'emp2@vulnshop.com', 'employee'),
('customer1', '123456', 'customer1@email.com', 'customer'),
('customer2', 'qwerty', 'customer2@email.com', 'customer'),
('customer3', 'password123', 'customer3@email.com', 'customer');

-- Products
INSERT INTO products (name, description, price, stock_quantity, created_by) VALUES
('Laptop Dell XPS 13', 'High-performance ultrabook with 16GB RAM', 1299.99, 10, 1),
('iPhone 15 Pro', 'Latest Apple smartphone with advanced camera', 999.99, 25, 1),
('Samsung Galaxy S24', 'Android flagship with AI features', 899.99, 15, 2),
('MacBook Air M2', 'Apple laptop with M2 chip', 1199.99, 8, 1),
('Sony WH-1000XM5', 'Noise-canceling wireless headphones', 399.99, 30, 2),
('iPad Pro 12.9"', 'Professional tablet for creative work', 1099.99, 12, 1),
('Gaming Mouse Logitech G Pro', 'Professional gaming mouse', 79.99, 50, 2),
('Mechanical Keyboard', 'RGB backlit mechanical keyboard', 149.99, 20, 1);

-- Orders
INSERT INTO orders (customer_id, employee_id, total_amount, status) VALUES
(4, 2, 1299.99, 'completed'),
(5, 2, 999.99, 'processing'),
(6, 3, 1549.98, 'pending'),
(4, 3, 479.98, 'completed'),
(5, 2, 1199.99, 'completed');

-- Order items
INSERT INTO order_items (order_id, product_id, quantity, unit_price) VALUES
(1, 1, 1, 1299.99),
(2, 2, 1, 999.99),
(3, 4, 1, 1199.99),
(3, 5, 1, 399.99),
(4, 5, 1, 399.99),
(4, 7, 1, 79.99),
(5, 4, 1, 1199.99);

