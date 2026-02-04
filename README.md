# RatTasks (RatDo)

> ⚠️ **WARNING: This application is intentionally vulnerable and designed for educational purposes only.**  
> Do not deploy this application to production or any public-facing environment without proper security hardening.

RatTasks is a Flask-based to-do list application intentionally designed with security vulnerabilities for educational purposes. It demonstrates common web application security issues including:

- **Stored XSS**: Task titles are rendered without proper escaping
- **Missing CSRF Protection**: State-changing operations lack CSRF tokens
- **IDOR/Broken Access Control**: Edit/delete/toggle operations don't verify task ownership
- **Weak Session Management**: Basic cookie sessions without advanced security features

This project is perfect for:
- Learning about web application security vulnerabilities
- Practicing bug bounty hunting techniques
- Teaching secure coding practices
- Security training and CTF challenges

## 📚 Documentation

- [ExploitGuide.md](ExploitGuide.md) - Step-by-step guide to exploiting vulnerabilities
- [DEPLOY.md](DEPLOY.md) - Kubernetes deployment guide

## 📋 Prerequisites

### Local Setup
- Python 3.11 or higher
- pip (Python package manager)

### Docker Setup
- Docker Engine 20.10 or higher
- Docker Compose (optional)

### Kubernetes Setup
- kubectl configured with cluster access
- Docker for building and pushing images

## 🚀 Running Locally (Without Docker)

### 1. Clone the Repository

```bash
git clone https://github.com/The-XSS-Rat/RatDo.git
cd RatDo
```

### 2. Create a Virtual Environment

```bash
# Create virtual environment
python3 -m venv venv

# Activate virtual environment
# On Linux/macOS:
source venv/bin/activate

# On Windows:
venv\Scripts\activate
```

### 3. Install Dependencies

```bash
pip install flask werkzeug
```

Or if a requirements file is needed:
```bash
pip install -r requirements.txt  # if exists
```

### 4. Run the Application

```bash
python RatDo.py
```

The application will start on `http://0.0.0.0:5000`

### 5. Access the Application

Open your browser and navigate to:
```
http://127.0.0.1:5000
```

### 6. Create an Account

1. Click "Register" to create a new account
2. Log in with your credentials
3. Start creating tasks and exploring the vulnerabilities!

### 7. Stop the Application

Press `Ctrl+C` in the terminal to stop the Flask development server.

### Notes for Local Development

- The application uses SQLite (`todo.db`) which will be created automatically in the project directory
- Tasks are automatically cleared every 30 minutes
- The default secret key is `dev-secret-change-me` (configured in the code)
- The database is initialized automatically on first run

## 🐳 Running with Docker

### Option 1: Using Pre-built Image

```bash
# Pull and run the latest image
docker run -p 5000:5000 unclerat/ratdo:latest
```

Access the application at `http://localhost:5000`

### Option 2: Build Your Own Image

#### 1. Build the Docker Image

```bash
docker build -t ratdo:latest .
```

#### 2. Run the Container

```bash
docker run -p 5000:5000 ratdo:latest
```

#### 3. Run with Persistent Database (Optional)

To persist the SQLite database between container restarts:

```bash
docker run -p 5000:5000 -v $(pwd)/data:/app ratdo:latest
```

#### 4. Run in Detached Mode

```bash
docker run -d -p 5000:5000 --name ratdo-app ratdo:latest
```

#### 5. View Logs

```bash
docker logs ratdo-app
```

#### 6. Stop and Remove Container

```bash
docker stop ratdo-app
docker rm ratdo-app
```

### Option 3: Using Docker Compose (Create docker-compose.yml)

Create a `docker-compose.yml` file:

```yaml
version: '3.8'

services:
  ratdo:
    build: .
    ports:
      - "5000:5000"
    volumes:
      - ./data:/app
    restart: unless-stopped
```

Run with Docker Compose:

```bash
# Start the application
docker-compose up -d

# View logs
docker-compose logs -f

# Stop the application
docker-compose down
```

## ☸️ Deploying to Kubernetes

### 1. Build and Push Docker Image

```bash
# Build the image
docker build -t your-docker-repo/ratdo:latest .

# Push to your container registry
docker push your-docker-repo/ratdo:latest
```

### 2. Update Deployment Configuration

Edit `k8s/deployment.yaml` and update the image reference:

```yaml
image: your-docker-repo/ratdo:latest
```

### 3. Deploy to Kubernetes

```bash
# Apply the deployment
kubectl apply -f k8s/deployment.yaml

# Check deployment status
kubectl get deployments
kubectl get pods

# Check service status
kubectl get svc ratdo
```

### 4. Access the Application

If using LoadBalancer:
```bash
kubectl get svc ratdo
# Note the EXTERNAL-IP and access the application
```

If using NodePort:
```bash
kubectl get svc ratdo
# Access via <node-ip>:<node-port>
```

### 5. Using Ingress (Optional)

Deploy the ingress configuration:

```bash
kubectl apply -f k8s/ingress.yaml
```

Make sure to update the host in `k8s/ingress.yaml` to match your domain.

### 6. View Logs

```bash
# Get pod name
kubectl get pods

# View logs
kubectl logs <pod-name>

# Follow logs
kubectl logs -f <pod-name>
```

### 7. Clean Up

```bash
kubectl delete -f k8s/deployment.yaml
kubectl delete -f k8s/ingress.yaml  # if deployed
```

## 🛠️ Development

### Project Structure

```
RatDo/
├── RatDo.py              # Main Flask application
├── Dockerfile            # Docker configuration
├── DEPLOY.md            # Kubernetes deployment guide
├── ExploitGuide.md      # Vulnerability exploitation guide
├── ExploitGuide.html    # HTML version of exploit guide
└── k8s/                 # Kubernetes manifests
    ├── deployment.yaml  # Deployment and Service
    └── ingress.yaml     # Ingress configuration
```

### Technology Stack

- **Backend**: Python Flask
- **Database**: SQLite
- **Frontend**: HTML with Tailwind CSS (via CDN)
- **Session Management**: Flask sessions with cookies
- **Password Hashing**: Werkzeug security utilities

### Environment Variables (Optional)

The application uses hardcoded defaults for simplicity. For production use, consider:

- `FLASK_SECRET_KEY`: Secret key for session management
- `DATABASE_PATH`: Path to SQLite database file
- `FLASK_ENV`: Set to 'production' for production deployments

## 🔒 Security Warnings

**This application is intentionally insecure!**

Known vulnerabilities include:
- ❌ Stored Cross-Site Scripting (XSS)
- ❌ Missing CSRF protection
- ❌ Insecure Direct Object References (IDOR)
- ❌ Broken Access Control
- ❌ Weak session management
- ❌ Hardcoded secrets

**Do NOT:**
- Deploy to production environments
- Use on public networks without proper isolation
- Store real or sensitive data
- Use as a template for real applications

**DO:**
- Use in isolated lab environments
- Run on local networks only
- Use for educational purposes
- Learn from the vulnerabilities

## 📖 Learning Resources

To learn how to exploit the vulnerabilities in this application:

1. Read the [ExploitGuide.md](ExploitGuide.md) for step-by-step exploitation instructions
2. Set up the application locally
3. Use browser DevTools to inspect requests and responses
4. Practice identifying and exploiting each vulnerability
5. Learn how to properly fix each security issue

## 🤝 Contributing

This is an educational project. Contributions that add new educational vulnerabilities or improve the learning experience are welcome.

## 📄 License

This project is for educational purposes only. Use responsibly and ethically.

## 👤 Author

The XSS Rat - [GitHub](https://github.com/The-XSS-Rat)

## 🙏 Acknowledgments

Built as a teaching tool for security education and bug bounty training.

---

**Remember**: Always practice ethical hacking. Only test systems you own or have explicit permission to test.
