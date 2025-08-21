from flask import Flask, render_template, request, session, jsonify, flash, redirect, url_for
from flask_login import LoginManager, UserMixin, login_user, login_required, logout_user, current_user
from werkzeug.security import generate_password_hash, check_password_hash
import google.generativeai as genai
from flask_sqlalchemy import SQLAlchemy
from sqlalchemy import desc # Import desc for ordering
from dotenv import load_dotenv
import os
from PIL import Image # Import Pillow for image processing
import io # Import io for BytesIO
import mimetypes # Import mimetypes to guess file types
import tempfile # For creating temporary files
from datetime import datetime # To store timestamp for chat sessions

load_dotenv()

app = Flask(__name__)
app.config['SECRET_KEY'] = os.getenv('SECRET_KEY')
GEMINI_API_KEY = os.getenv("GEMINI_API_KEY")
if not GEMINI_API_KEY:
    raise ValueError("GEMINI_API_KEY environment variable not set.")

genai.configure(api_key=GEMINI_API_KEY)

# Initialize the generative model
# We will create a new GenerativeModel instance for each chat to manage history
# model = genai.GenerativeModel('gemini-2.5-flash') # This line will be removed/modified

app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///chat.db'
db = SQLAlchemy(app)

# Define allowed extensions for file uploads
ALLOWED_EXTENSIONS = {'png', 'jpg', 'jpeg', 'gif', 'webp', 'pdf', 'docx'}

def allowed_file(filename):
    """Checks if the file extension is allowed."""
    return '.' in filename and \
           filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS

# --- Database Models ---
class User(UserMixin, db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(150), unique=True)
    email = db.Column(db.String(150), unique=True, nullable=False)
    password = db.Column(db.String(150), nullable=False)
    chat_sessions = db.relationship('ChatSession', backref='user', lazy=True, cascade="all, delete-orphan")

class ChatSession(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    # A title for the chat session, automatically generated or set by the user
    title = db.Column(db.String(255), nullable=True)
    messages = db.relationship('ChatMessage', backref='chat_session', lazy=True, cascade="all, delete-orphan")

class ChatMessage(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    chat_session_id = db.Column(db.Integer, db.ForeignKey('chat_session.id'), nullable=False)
    sender = db.Column(db.String(50), nullable=False) # 'user' or 'ai'
    text = db.Column(db.Text, nullable=False)
    # We can store a reference to the uploaded file if it was part of the message
    file_path = db.Column(db.String(255), nullable=True)
    timestamp = db.Column(db.DateTime, default=datetime.utcnow)
    rating = db.Column(db.Integer, nullable=True) # 1 for thumbs up, 0 for thumbs down, None for no rating

# --- Login Manager Initialization ---
login_manager = LoginManager(app)
login_manager.login_view = 'login'

@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))

# --- Before Request Hook to Create Tables ---
@app.before_request
def create_tables_if_not_exist():
    # Only create tables if running within an application context
    # This prevents issues with commands like 'flask db upgrade' if using migrations
    with app.app_context():
        db.create_all()

# --- Helper function for shortening titles ---
def get_short_title(text, max_length=20):
    """Shortens a string to a specified max_length, adding an ellipsis if truncated."""
    if len(text) > max_length:
        return text[:max_length].strip() + "..."
    return text.strip()

# --- Routes ---
@app.route('/login', methods=['GET', 'POST'])
def login():
    if current_user.is_authenticated:
        return redirect(url_for('home'))
    if request.method == 'POST':
        username = request.form.get('username')
        password = request.form.get('password')

        user = User.query.filter_by(username=username).first()

        if user and check_password_hash(user.password, password):
            login_user(user) 
            flash('Logged in successfully!', 'success')
            return redirect(url_for('home')) 
        else:
            flash('Login Unsuccessful. Please check username and password', 'danger')
            return render_template('login.html')
    return render_template('login.html')

@app.route('/register', methods=['GET', 'POST'])
def register():
    if current_user.is_authenticated:
        return redirect(url_for('home'))
    if request.method == 'POST':
        username = request.form.get('username')
        email = request.form.get('email') 
        password = request.form.get('password')

        existing_user = User.query.filter_by(username=username).first()
        if existing_user:
            flash('Username already exists. Please choose a different one.', 'warning')
            return render_template('register.html')
        
        existing_email = User.query.filter_by(email=email).first()
        if existing_email:
            flash('Another user has registered with this email. Please choose a different one.', 'warning')
            return render_template('register.html')

        hashed_password = generate_password_hash(password, method='pbkdf2:sha256')
        new_user = User(username=username, email=email, password=hashed_password)
        db.session.add(new_user)
        db.session.commit()
        flash('Account created successfully! You can now log in.', 'success')
        return redirect(url_for('login'))
    return render_template('register.html')

@app.route('/logout', methods=['POST'])
@login_required
def logout():
    logout_user()
    flash('You have been logged out.', 'info')
    return redirect(url_for('login')) # Redirect to login page after logout

@app.route('/')
@login_required
def home():
    # Fetch only the last 9 chat sessions for the current user
    user_chat_sessions = ChatSession.query.filter_by(user_id=current_user.id).order_by(desc(ChatSession.created_at)).limit(9).all()

    processed_sessions = []
    # If there are no chat sessions, create a new one automatically
    if not user_chat_sessions:
        new_session = ChatSession(user_id=current_user.id, title="New Chat")
        db.session.add(new_session)
        db.session.commit()
        # Add the new session to the list to be processed
        user_chat_sessions = [new_session]
        session['current_chat_session_id'] = new_session.id
    else:
        # If a current_chat_session_id is not set in session, use the most recent one
        if 'current_chat_session_id' not in session and user_chat_sessions:
            session['current_chat_session_id'] = user_chat_sessions[0].id
        # Ensure the session ID in the cookie is valid for the current user
        valid_session_ids = [s.id for s in user_chat_sessions]
        if 'current_chat_session_id' in session and session['current_chat_session_id'] not in valid_session_ids:
            session['current_chat_session_id'] = user_chat_sessions[0].id

    # Create a list of sessions with pre-processed titles for the template
    for session_obj in user_chat_sessions:
        # Find the first user message in the session to use for the title
        first_user_message = ChatMessage.query.filter_by(chat_session_id=session_obj.id, sender='user').order_by(ChatMessage.timestamp).first()

        # If a first message exists, use a shortened version as the title. Otherwise, use the existing title or a default.
        title = get_short_title(first_user_message.text) if first_user_message else session_obj.title or 'Untitled Chat'
        
        processed_sessions.append({
            'id': session_obj.id,
            'title': title
        })

    # Get the messages for the currently active chat session
    current_chat_id = session.get('current_chat_session_id')
    current_chat_messages = []
    if current_chat_id:
        current_chat = ChatSession.query.get(current_chat_id)
        if current_chat and current_chat.user_id == current_user.id: # Security check
            current_chat_messages = ChatMessage.query.filter_by(chat_session_id=current_chat_id).order_by(ChatMessage.timestamp).all()

    return render_template('index.html', 
                           chat_sessions=processed_sessions, # Pass the new list
                           current_chat_messages=current_chat_messages,
                           current_chat_session_id=current_chat_id)

@app.route('/new_chat_session', methods=['POST'])
@login_required
def new_chat_session():
    new_session = ChatSession(user_id=current_user.id, title="New Chat")
    db.session.add(new_session)
    db.session.commit()
    session['current_chat_session_id'] = new_session.id
    return jsonify({"success": True, "session_id": new_session.id, "title": new_session.title})

@app.route('/get_chat_history/<int:session_id>', methods=['GET'])
@login_required
def get_chat_history(session_id):
    chat_session = ChatSession.query.filter_by(id=session_id, user_id=current_user.id).first()
    if not chat_session:
        return jsonify({"error": "Chat session not found or unauthorized"}), 404

    messages = ChatMessage.query.filter_by(chat_session_id=session_id).order_by(ChatMessage.timestamp).all()
    # Update the session to reflect the newly loaded chat
    session['current_chat_session_id'] = session_id
    
    chat_history_data = [
        {"sender": msg.sender, "text": msg.text, "file_path": msg.file_path, "rating": msg.rating, "id": msg.id}
        for msg in messages
    ]
    return jsonify({"messages": chat_history_data, "current_session_id": session_id})


@app.route('/ask', methods=['POST']) 
@login_required
def ask():
    user_message = request.form.get('message')
    uploaded_file = request.files.get('file') # Get the uploaded file
    current_chat_session_id = session.get('current_chat_session_id')

    if not current_chat_session_id:
        # If no session ID, create a new one
        new_session = ChatSession(user_id=current_user.id, title="New Chat")
        db.session.add(new_session)
        db.session.commit()
        session['current_chat_session_id'] = new_session.id
        current_chat_session_id = new_session.id

    # Retrieve the chat session to check if it's new and needs a title
    current_chat_session = ChatSession.query.get(current_chat_session_id)
    if current_chat_session and (current_chat_session.title is None or current_chat_session.title == "New Chat"):
        # Set the title to a shortened version of the first user message
        current_chat_session.title = get_short_title(user_message)
        db.session.commit()

    # Retrieve previous messages for the current chat session to provide context
    previous_messages_db = ChatMessage.query.filter_by(chat_session_id=current_chat_session_id).order_by(ChatMessage.timestamp).all()
    
    gemini_chat_history = []
    for msg in previous_messages_db:
        gemini_chat_history.append({"role": "user" if msg.sender == "user" else "model", "parts": [msg.text]})

    parts = []
    if user_message:
        parts.append(user_message)

    if uploaded_file:
        filename = uploaded_file.filename
        if not allowed_file(filename):
            return jsonify({"error": "Unsupported file type. Please upload an image (png, jpg, jpeg, gif, webp), a PDF, or a DOCX file."}), 400

        mime_type, _ = mimetypes.guess_type(filename) 

        if mime_type and mime_type.startswith('image/'):
            try:
                image_data = uploaded_file.read()
                image = Image.open(io.BytesIO(image_data))
                parts.append(image)
            except Exception as e:
                return jsonify({"error": f"Failed to process image: {str(e)}"}), 400
        elif mime_type == 'application/pdf':
            try:
                with tempfile.NamedTemporaryFile(delete=False, suffix=".pdf") as temp_pdf:
                    temp_pdf.write(uploaded_file.read())
                    temp_pdf_path = temp_pdf.name
                
                uploaded_gemini_file = genai.upload_file(path=temp_pdf_path, display_name=filename)
                parts.append(uploaded_gemini_file)
                os.remove(temp_pdf_path)
            except Exception as e:
                if 'temp_pdf_path' in locals() and os.path.exists(temp_pdf_path):
                    os.remove(temp_pdf_path)
                return jsonify({"error": f"Failed to process PDF: {str(e)}"}), 400
        elif mime_type == 'application/vnd.openxmlformats-officedocument.wordprocessingml.document':
            try:
                with tempfile.NamedTemporaryFile(delete=False, suffix=".docx") as temp_docx:
                    temp_docx.write(uploaded_file.read())
                    temp_docx_path = temp_docx.name
                
                uploaded_gemini_file = genai.upload_file(path=temp_docx_path, display_name=filename)
                parts.append(uploaded_gemini_file)
                os.remove(temp_docx_path)
            except Exception as e:
                if 'temp_docx_path' in locals() and os.path.exists(temp_docx_path):
                    os.remove(temp_docx_path)
                return jsonify({"error": f"Failed to process DOCX: {str(e)}"}), 400
        else:
            return jsonify({"error": "Unsupported file type. Please upload an image (png, jpg, jpeg, gif, webp), a PDF, or a DOCX file."}), 400

    if not parts:
        return jsonify({"error": "No message or file provided."}), 400

    try:
        # Start a chat session with the model using the retrieved history
        chat_session = genai.GenerativeModel('gemini-2.5-flash').start_chat(history=gemini_chat_history)
        response = chat_session.send_message(parts)

        # Save user message to the database
        user_msg_db = ChatMessage(chat_session_id=current_chat_session_id, sender="user", text=user_message)
        db.session.add(user_msg_db)
        
        # Save AI reply to the database
        ai_reply_db = ChatMessage(chat_session_id=current_chat_session_id, sender="ai", text=response.text)
        db.session.add(ai_reply_db)
        db.session.commit()

        return jsonify({"reply": response.text, "session_id": current_chat_session_id, "ai_message_id": ai_reply_db.id})
    except Exception as e:
        print(f"An error occurred: {e}")
        return jsonify({"error": "An internal server error occurred.", "details": str(e)}), 500
      
@app.route('/rate', methods=['POST'])
@login_required
def rate():
    data = request.json
    score = data.get('score')
    message_id = data.get('message_id') # Assuming you'll pass the message ID to rate

    if message_id is None or score is None:
        return jsonify({"error": "Missing message_id or score"}), 400

    message = ChatMessage.query.get(message_id)
    if not message or message.chat_session.user_id != current_user.id:
        return jsonify({"error": "Message not found or unauthorized"}), 404

    message.rating = score
    db.session.commit()
    print(f"Feedback received for message {message_id}: {score}")
    return jsonify({"success": True}), 200

@app.route('/clear_history', methods=['POST'])
@login_required
def clear_history():
    try:
        # Delete all chat messages and sessions for the current user
        # The cascade="all, delete-orphan" on the relationships ensures
        # that deleting a ChatSession also deletes all its ChatMessages.
        # We can delete all sessions at once.
        ChatSession.query.filter_by(user_id=current_user.id).delete()
        
        # Commit the deletion
        db.session.commit()

        # Create a new, fresh chat session for the user
        new_session = ChatSession(user_id=current_user.id, title="New Chat")
        db.session.add(new_session)
        db.session.commit()
        session['current_chat_session_id'] = new_session.id

        return jsonify({"success": True})
    except Exception as e:
        db.session.rollback() # Roll back the transaction in case of an error
        print(f"Error clearing chat history: {e}")
        return jsonify({"success": False, "error": str(e)}), 500

# --- Run the App ---
if __name__ == '__main__':
    app.run(debug=True)