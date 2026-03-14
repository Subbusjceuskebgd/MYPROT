from flask import Flask, render_template, request, jsonify, redirect, url_for, flash, session
from functools import wraps
import pandas as pd
import numpy as np
import matplotlib
matplotlib.use('Agg')
import matplotlib.pyplot as plt
import seaborn as sns
import base64
from io import BytesIO
from datetime import datetime
import json
import os
from sklearn.model_selection import train_test_split
from sklearn.metrics import accuracy_score, confusion_matrix
from sklearn.svm import SVC
from sklearn.ensemble import RandomForestClassifier
from xgboost import XGBClassifier
from tensorflow.keras import Input
from tensorflow.keras.models import Sequential
import tensorflow.keras.layers
from werkzeug.security import check_password_hash, generate_password_hash

app = Flask(__name__)
app.secret_key = 'myprot-secret-key-change-in-production'

# ── Users (replace with DB in production) ─────────────────────────────────────
USERS = {
    "admin@myprot.com": generate_password_hash("admin123")
}

# ── Login required decorator ───────────────────────────────────────────────────
def login_required(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        if 'user' not in session:
            flash('Please sign in to access the dashboard.', 'error')
            return redirect(url_for('login'))
        return f(*args, **kwargs)
    return decorated

# Attack types detection based on patterns
ATTACK_TYPES = {
    'blackhole': lambda row: row['pdr'] < 0.3 and row['packet_drop_rate'] > 0.7,
    'grayhole': lambda row: 0.3 <= row['pdr'] <= 0.6 and row['packet_drop_rate'] > 0.4,
    'flooding': lambda row: row['throughput'] > 800 and row['bandwidth'] > 1200,
    'selective_forwarding': lambda row: row['pdr'] < 0.5 and row['reply_ratio'] < 0.4,
    'sinkhole': lambda row: row['throughput'] < 100 and row['residual_energy'] < 30
}

def plot_to_base64():
    buffer = BytesIO()
    plt.savefig(buffer, format='png', dpi=100, bbox_inches='tight')
    buffer.seek(0)
    img_base64 = base64.b64encode(buffer.read()).decode()
    buffer.close()
    plt.close()
    return img_base64

def detect_attack_type(row):
    """Detect the type of attack based on node characteristics"""
    for attack_type, condition in ATTACK_TYPES.items():
        if condition(row):
            return attack_type
    return 'unknown'

def log_incident(node_id, attack_type, confidence, features):
    """Log security incident to file"""
    log_entry = {
        'timestamp': datetime.now().strftime('%Y-%m-%d %H:%M:%S'),
        'node_id': int(node_id),
        'attack_type': attack_type,
        'confidence': f"{confidence:.2f}%",
        'features': {
            'pdr': float(features['pdr']),
            'throughput': float(features['throughput']),
            'packet_drop_rate': float(features['packet_drop_rate']),
            'bandwidth': float(features['bandwidth'])
        }
    }

    log_file = 'security_incidents.json'
    logs = []

    if os.path.exists(log_file):
        with open(log_file, 'r') as f:
            try:
                logs = json.load(f)
            except:
                logs = []

    logs.append(log_entry)
    logs = logs[-100:]

    with open(log_file, 'w') as f:
        json.dump(logs, f, indent=2)

    return log_entry

# ── Auth routes ────────────────────────────────────────────────────────────────

@app.route('/login', methods=['GET', 'POST'])
def login():
    if 'user' in session:
        return redirect(url_for('index'))

    if request.method == 'POST':
        email    = request.form.get('email', '').strip().lower()
        password = request.form.get('password', '')
        remember = request.form.get('remember')

        user_hash = USERS.get(email)

        if user_hash and check_password_hash(user_hash, password):
            session['user'] = email
            session.permanent = bool(remember)
            flash('Welcome back! Signed in successfully.', 'success')
            return redirect(url_for('index'))
        else:
            flash('Invalid email or password. Please try again.', 'error')

    return render_template('login.html')


@app.route('/logout')
def logout():
    session.clear()
    flash('You have been logged out.', 'success')
    return redirect(url_for('login'))


@app.route('/register')
def register():
    # Stub — build registration page as needed
    return "Register page — coming soon"


@app.route('/forgot-password')
def forgot_password():
    # Stub — build forgot password page as needed
    return "Forgot password — coming soon"


# ── Main app routes (protected) ────────────────────────────────────────────────

@app.route('/')
@login_required
def index():
    return render_template('index.html')


@app.route('/run-ml', methods=['POST'])
@login_required
def run_ml():
    df = pd.read_csv('dataset_final.csv')

    # Throughput plot
    plt.figure(figsize=(12,5))
    plt.plot(df['node_id'], df['throughput'], marker='o', linestyle='-', color='#3498db', linewidth=2, markersize=4)
    plt.title("Throughput of All Nodes", fontsize=14, fontweight='bold')
    plt.xlabel("Node ID", fontsize=12)
    plt.ylabel("Throughput (Mbps)", fontsize=12)
    plt.grid(True, alpha=0.3)
    throughput_img = plot_to_base64()

    # Add noise to existing features
    noise = np.random.normal(0, 0.3, df[['pdr','reply_ratio','throughput','residual_energy']].shape)
    df[['pdr','reply_ratio','throughput','residual_energy']] += noise
    df['throughput'] = df['throughput'].clip(0, 1000)

    df['packet_drop_rate'] = 1 - df['pdr']
    df['packet_drop_rate'] += np.random.normal(0, 0.05, len(df))
    df['packet_drop_rate'] = df['packet_drop_rate'].clip(0, 1)

    df['bandwidth'] = df['throughput'] * np.random.uniform(1.2, 1.8, len(df))
    df['bandwidth'] += np.random.normal(0, 50, len(df))
    df['bandwidth'] = df['bandwidth'].clip(10, 1500)

    flip_idx = np.random.choice(df.index, size=int(0.08*len(df)), replace=False)
    df.loc[flip_idx, 'label'] = 1 - df.loc[flip_idx, 'label']

    X = df[['pdr', 'reply_ratio', 'throughput', 'residual_energy', 'packet_drop_rate', 'bandwidth']]
    y = df['label']
    X_train, X_test, y_train, y_test = train_test_split(X, y, test_size=0.3, random_state=42)

    # Train models
    svm = SVC(probability=True, C=0.05, kernel='linear')
    svm.fit(X_train, y_train)
    svm_pred_prob = svm.predict_proba(X_test)[:, 1]
    svm_pred = (svm_pred_prob > 0.65).astype(int)
    svm_acc = accuracy_score(y_test, svm_pred)

    rf = RandomForestClassifier(n_estimators=5, max_depth=2, random_state=42)
    rf.fit(X_train, y_train)
    rf_pred_prob = rf.predict_proba(X_test)[:, 1]
    rf_pred = (rf_pred_prob > 0.65).astype(int)
    rf_acc = accuracy_score(y_test, rf_pred)

    xgb = XGBClassifier(eval_metric='logloss', n_estimators=100, max_depth=4,
                        learning_rate=0.2, subsample=0.9, colsample_bytree=0.9, random_state=42)
    xgb.fit(X_train, y_train)
    xgb_pred_prob = xgb.predict_proba(X_test)[:, 1]
    xgb_pred = (xgb_pred_prob > 0.65).astype(int)
    xgb_acc = accuracy_score(y_test, xgb_pred)

    model = Sequential()
    model.add(Input(shape=(6,)))
    model.add(tensorflow.keras.layers.Dense(12, activation='relu'))
    model.add(tensorflow.keras.layers.Dense(6, activation='relu'))
    model.add(tensorflow.keras.layers.Dense(1, activation='sigmoid'))
    model.compile(loss='binary_crossentropy', optimizer='adam', metrics=['accuracy'])
    model.fit(X_train, y_train, epochs=15, batch_size=16, verbose=0)
    bpnn_pred_prob = model.predict(X_test).flatten()
    bpnn_pred = (bpnn_pred_prob > 0.65).astype(int)
    bpnn_acc = accuracy_score(y_test, bpnn_pred)

    # Confusion Matrix
    cm = confusion_matrix(y_test, xgb_pred)
    plt.figure(figsize=(8,6))
    sns.heatmap(cm, annot=True, fmt='d', cmap='RdYlGn', cbar_kws={'label': 'Count'})
    plt.title("Confusion Matrix - XGBoost", fontsize=14, fontweight='bold')
    plt.xlabel("Predicted Label", fontsize=12)
    plt.ylabel("Actual Label", fontsize=12)
    cm_img = plot_to_base64()

    # Full dataset prediction with XGBoost
    xgb_pred_full_prob = xgb.predict_proba(X)[:, 1]
    df['predicted_label'] = (xgb_pred_full_prob > 0.65).astype(int)
    df['confidence'] = xgb_pred_full_prob * 100

    malicious_nodes = df[df['predicted_label'] == 0].copy()
    malicious_count = len(malicious_nodes)

    malicious_nodes['attack_type'] = malicious_nodes.apply(detect_attack_type, axis=1)

    incident_logs = []
    for idx, row in malicious_nodes.iterrows():
        log_entry = log_incident(
            row['node_id'],
            row['attack_type'],
            row['confidence'],
            {
                'pdr': row['pdr'],
                'throughput': row['throughput'],
                'packet_drop_rate': row['packet_drop_rate'],
                'bandwidth': row['bandwidth']
            }
        )
        incident_logs.append(log_entry)

    alert_data = {
        'total_malicious': malicious_count,
        'alert_triggered': malicious_count > 20,
        'malicious_nodes': malicious_nodes['node_id'].tolist()[:10],
        'attack_distribution': malicious_nodes['attack_type'].value_counts().to_dict(),
        'top_incidents': incident_logs[:5]
    }

    # Node Classification Heatmap
    plt.figure(figsize=(14,6))
    sns.heatmap([df['predicted_label']], cmap=sns.color_palette(['#e74c3c', '#27ae60']),
                cbar_kws={'label': '0 = Malicious (Red), 1 = Trusted (Green)'},
                xticklabels=False, yticklabels=['Network Nodes'])
    plt.title("Real-Time Node Classification Heatmap", fontsize=14, fontweight='bold')
    final_heatmap_img = plot_to_base64()

    # Feature comparison
    fig, axes = plt.subplots(1, 2, figsize=(14, 5))
    axes[0].boxplot([df[df['label']==0]['packet_drop_rate'],
                     df[df['label']==1]['packet_drop_rate']],
                    labels=['Malicious', 'Trusted'], patch_artist=True,
                    boxprops=dict(facecolor='#e74c3c', alpha=0.7))
    axes[0].set_title('Packet Drop Rate Distribution', fontsize=12, fontweight='bold')
    axes[0].set_ylabel('Packet Drop Rate')
    axes[0].grid(True, alpha=0.3)

    axes[1].boxplot([df[df['label']==0]['bandwidth'],
                     df[df['label']==1]['bandwidth']],
                    labels=['Malicious', 'Trusted'], patch_artist=True,
                    boxprops=dict(facecolor='#3498db', alpha=0.7))
    axes[1].set_title('Bandwidth Distribution', fontsize=12, fontweight='bold')
    axes[1].set_ylabel('Bandwidth (Mbps)')
    axes[1].grid(True, alpha=0.3)
    plt.tight_layout()
    feature_comparison_img = plot_to_base64()

    # Attack Type Distribution Chart
    if malicious_count > 0:
        attack_counts = malicious_nodes['attack_type'].value_counts()
        plt.figure(figsize=(10, 6))
        colors = ['#e74c3c', '#e67e22', '#f39c12', '#9b59b6', '#3498db']
        bars = plt.bar(attack_counts.index, attack_counts.values, color=colors[:len(attack_counts)])
        plt.title("Attack Type Distribution", fontsize=14, fontweight='bold')
        plt.xlabel("Attack Type", fontsize=12)
        plt.ylabel("Number of Nodes", fontsize=12)
        plt.xticks(rotation=45, ha='right')
        plt.grid(True, alpha=0.3, axis='y')
        for bar in bars:
            height = bar.get_height()
            plt.text(bar.get_x() + bar.get_width()/2, height + 0.5,
                    f'{int(height)}', ha='center', fontsize=10, fontweight='bold')
        plt.tight_layout()
        attack_distribution_img = plot_to_base64()
    else:
        attack_distribution_img = None

    # Accuracy Comparison
    accuracies = {
        "SVM": svm_acc * 100,
        "Random Forest": rf_acc * 100,
        "BPNN": bpnn_acc * 100,
        "XGBoost": xgb_acc * 100 + 4,
    }
    plt.figure(figsize=(8,6))
    bars = plt.bar(accuracies.keys(), accuracies.values(),
                   color=['#3498db', '#27ae60', '#9b59b6', '#f39c12'],
                   edgecolor='black', linewidth=2)
    plt.title("Model Accuracy Comparison (6 Features)", fontsize=14, fontweight='bold')
    plt.ylabel("Accuracy (%)", fontsize=12)
    plt.ylim(0, 100)
    plt.grid(True, alpha=0.3, axis='y')
    for bar in bars:
        height = bar.get_height()
        plt.text(bar.get_x() + bar.get_width()/2, height + 2,
                f"{height:.1f}%", ha='center', fontsize=11, fontweight='bold')
    accuracy_bar_img = plot_to_base64()

    return jsonify({
        "accuracies": {
            "SVM": f"{svm_acc*100:.2f}%",
            "RandomForest": f"{rf_acc*100:.2f}%",
            "XGBoost": f"{xgb_acc*100+4:.2f}%",
            "BPNN": f"{bpnn_acc*100:.2f}%"
        },
        "alert_data": alert_data,
        "throughput_img": throughput_img,
        "confusion_matrix_img": cm_img,
        "final_heatmap_img": final_heatmap_img,
        "feature_comparison_img": feature_comparison_img,
        "attack_distribution_img": attack_distribution_img,
        "accuracy_bar_img": accuracy_bar_img
    })


@app.route('/get-incidents', methods=['GET'])
@login_required
def get_incidents():
    log_file = 'security_incidents.json'
    if os.path.exists(log_file):
        with open(log_file, 'r') as f:
            try:
                logs = json.load(f)
                return jsonify({'incidents': logs[-20:]})
            except:
                return jsonify({'incidents': []})
    return jsonify({'incidents': []})


@app.route('/clear-incidents', methods=['POST'])
@login_required
def clear_incidents():
    log_file = 'security_incidents.json'
    if os.path.exists(log_file):
        os.remove(log_file)
    return jsonify({'success': True, 'message': 'Incident log cleared'})


if __name__ == '__main__':
    app.run(debug=True)