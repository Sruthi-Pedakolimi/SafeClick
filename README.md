# 🛡️ Safe-Click: Intelligent Phishing Detection Platform

> *Protecting users from cyber threats through advanced machine learning and real-time URL analysis*

Safe-Click represents a cutting-edge approach to cybersecurity, utilizing sophisticated machine learning algorithms to identify and prevent phishing attacks before they can compromise user data. Our system combines multiple classification models with advanced feature engineering to deliver unprecedented accuracy in threat detection.

## 🎯 Project Mission

Phishing attacks continue to evolve, exploiting human trust and technical vulnerabilities to steal sensitive information. Safe-Click addresses this challenge by providing an intelligent, interpretable, and user-centric solution that empowers individuals and organizations to browse safely.

## ✨ Core Capabilities

🚀 **Multi-Algorithm Detection** – Leverages **Random Forest, Gradient Boosting, and Decision Tree** algorithms for comprehensive analysis.  
🚀 **Smart Data Processing** – Automated feature optimization reduces complexity while maximizing detection accuracy.  
🚀 **Lightning-Fast Analysis** – Users receive **instant phishing alerts** within seconds of URL submission.  
🚀 **Enterprise-Grade Backend** – Built on **Django framework** for security, scalability, and reliability.  
🚀 **Modern User Experience** – Sleek interface designed with **HTML5, CSS3, and JavaScript**.  
🚀 **Trust Through Transparency** – Shows exactly why a URL is flagged as suspicious or safe.



## 🏛️ System Design

### Architecture Overview

```
┌─────────────────┐    ┌──────────────────┐    ┌─────────────────┐
│   User Input    │───▶│  Django Backend  │───▶│  ML Processing  │
│   Interface     │    │                  │    │    Engine       │
└─────────────────┘    └──────────────────┘    └─────────────────┘
                                │                        │
                                ▼                        ▼
┌─────────────────┐    ┌──────────────────┐    ┌─────────────────┐
│ Result Display  │◀───│  Response        │◀───│ Classification  │
│ & Explanations  │    │  Processing      │    │ & Analysis      │
└─────────────────┘    └──────────────────┘    └─────────────────┘
```

### Technology Infrastructure

| Component | Technology | Purpose |
|-----------|------------|---------|
| **Backend Framework** | Django + Python | Request processing, model integration |
| **ML Pipeline** | scikit-learn | Model training, prediction, evaluation |
| **Frontend** | HTML5, CSS3, JavaScript | User interface and interaction |
| **Data Processing** | pandas, NumPy | Feature extraction and preprocessing |
| **Visualization** | Matplotlib | Performance analysis and insights |

## 🚀 Quick Start Guide

### Environment Setup

```bash
# Clone repository
git clone https://github.com/yourusername/safe-click.git
cd safe-click

# Create isolated environment
python -m venv safe_click_env
source safe_click_env/bin/activate  # Windows: safe_click_env\Scripts\activate

# Install dependencies
pip install -r requirements.txt
```

### Application Launch

```bash
# Initialize database
python manage.py makemigrations
python manage.py migrate

# Start development server
python manage.py runserver

# Access application
# Navigate to: http://localhost:8000
```

## 📊 Results

**Superior Accuracy**: **98% accuracy** using Gradient Boosting and Random Forest. 

**Optimized Processing**: Reduced feature complexity from **49 to 37 variables** for faster analysis.  

**User-Centric Design**: Combines high performance with **clear, understandable explanations**


## Youtube Link
https://youtu.be/AZJMkY0hHlQ?si=LG5uyGzn_oH8jva5
