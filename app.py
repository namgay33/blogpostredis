import os
import bcrypt
from flask import Flask, render_template, request, redirect, url_for, flash, make_response, abort
from flask_login import LoginManager, UserMixin, login_user, logout_user, login_required, current_user
import redis
from werkzeug.utils import secure_filename

# Initialize Flask app
app = Flask(__name__)
app.secret_key = 'redisapp'  
# Set up upload folder
UPLOAD_FOLDER = os.path.join('static', 'uploads') 

app.config['UPLOAD_FOLDER'] = UPLOAD_FOLDER
app.config['MAX_CONTENT_LENGTH'] = 16 * 1024 * 1024  # Limit upload size to 16MB

# Ensure the upload folder exists
os.makedirs(UPLOAD_FOLDER, exist_ok=True)

# Initialize Flask-Login
login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = 'login'

# Redis Setup
redis_client = redis.Redis(host='localhost', port=6379, db=0)

# Redis keys for incrementing IDs
USER_ID_KEY = "user_id_seq"
POST_ID_KEY = "post_id_seq"

# User Class
class User(UserMixin):
    def __init__(self, id, username):
        self.id = id
        self.username = username

@login_manager.user_loader
def load_user(user_id):
    """Load user from Redis using user_id."""
    user_data = redis_client.hgetall(f"user:{user_id}")
    if user_data:
        return User(user_id, user_data[b'username'].decode('utf-8'))
    return None

@app.route('/')
@login_required
def index():
    """Fetch and display all posts on the home dashboard."""
    user_posts = []
    
    # Attempt to retrieve user posts from Redis
    try:
        for key in redis_client.scan_iter(f"post:{current_user.id}:*"):
            post = redis_client.hgetall(key)
            if post:  # Check if the post is not empty
                # Decode post data and add post_id to the post dictionary
                post_data = {k.decode('utf-8'): v.decode('utf-8') for k, v in post.items()}
                
                # Extract the post_id from the Redis key (the last part of the key)
                post_id = key.decode('utf-8').split(':')[-1]
                
                # Add the extracted post_id to the post data
                post_data['_id'] = post_id
                # Append the complete post data to the list
                user_posts.append(post_data)
    except Exception as e:
        app.logger.error(f"Error fetching posts for user {current_user.id}: {e}")
        return render_template('index.html', posts=[], error="Error fetching posts. Please try again.")

    # Check if user has no posts
    if not user_posts:
        app.logger.info(f"User {current_user.id} has no posts.")
        return render_template('index.html', posts=[], message="You have no posts yet.")

    return render_template('index.html', posts=user_posts)

@app.route('/signup', methods=['GET', 'POST'])
def signup():
    """User signup for creating a new account."""
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        confirm_password = request.form['confirm_password']

        if password != confirm_password:
            flash("Passwords do not match!")
            return render_template('signup.html')

        # Check if username already exists
        for key in redis_client.scan_iter("user:*"):
            user = redis_client.hgetall(key)
            if user[b'username'].decode('utf-8') == username:
                flash("Username already exists!")
                return render_template('signup.html')

        # Create a new user
        user_id = redis_client.incr(USER_ID_KEY)
        hashed_password = bcrypt.hashpw(password.encode('utf-8'), bcrypt.gensalt())
        redis_client.hset(f"user:{user_id}", mapping={
            "username": username,
            "password": hashed_password
        })

        flash("Signup successful! Please log in.")
        return redirect(url_for('login'))

    return render_template('signup.html')

@app.route('/login', methods=['GET', 'POST'])
def login():
    """Handle user login."""
    if current_user.is_authenticated:
        return redirect(url_for('index'))

    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']

        # Find the user by username
        for key in redis_client.scan_iter("user:*"):
            user_data = redis_client.hgetall(key)
            if user_data and user_data[b'username'].decode('utf-8') == username:
                if bcrypt.checkpw(password.encode('utf-8'), user_data[b'password']):
                    user_id = key.decode('utf-8').split(":")[1]
                    user_obj = User(user_id, username)
                    login_user(user_obj)
                    return redirect(url_for('index'))

        flash('Invalid username or password!')

    response = make_response(render_template('login.html'))
    response.headers['Cache-Control'] = 'no-store'
    return response

@app.route('/logout')
@login_required
def logout():
    """Log the user out and redirect to the home page."""
    logout_user()
    response = make_response(redirect(url_for('index')))
    response.headers['Cache-Control'] = 'no-store'
    return response

@app.route('/create', methods=['GET', 'POST'])
@login_required
def create():
    """Create a new post/note."""
    if request.method == 'POST':
        title = request.form['title']
        content = request.form['content']
        tags = request.form['tags']

        # Handle image upload (optional)
        image_path = None

        if 'image' in request.files:
            file = request.files['image']
            if file.filename != '':
                filename = secure_filename(file.filename)
                file.save(os.path.join(app.config['UPLOAD_FOLDER'], filename))
                image_path = 'uploads/' + filename

        # Create a new post with auto-incremented post ID
        # Increment the post ID for unique identifier
        post_id = redis_client.incr(POST_ID_KEY)  
        
        # Store the post in Redis, including the post ID in the hash
        redis_client.hset(f"post:{current_user.id}:{post_id}", mapping={
            "_id": post_id,  
            "title": title,
            "content": content,
            "tags": tags,
            "image_path": image_path or "",
            "user_id": str(current_user.id)  # Ensure user_id is stored as a string
        })

        flash('Post/Note created successfully!')
        return redirect(url_for('index'))

    return render_template('create.html', user_name=current_user.username)


@app.route('/edit/<post_id>', methods=['GET', 'POST'])
@login_required
def edit(post_id):
    """Edit an existing post/note."""
    post_key = f"post:{current_user.id}:{post_id}"
    post = redis_client.hgetall(post_key)

    if not post:
        flash('Post not found or you do not have permission to edit this post.')
        return redirect(url_for('index'))

    if request.method == 'POST':
        update_data = {
            'title': request.form['title'],
            'content': request.form['content'],
            'tags': request.form['tags']
        }

        # Handle image upload
        image_file = request.files.get('image')
        if image_file and image_file.filename != '':
            if post.get(b'image_path'):
                old_image_path = os.path.join(app.config['UPLOAD_FOLDER'], post[b'image_path'].decode('utf-8').split('/')[-1])
                if os.path.exists(old_image_path):
                    os.remove(old_image_path)

            image_filename = secure_filename(image_file.filename)
            image_path = os.path.join(app.config['UPLOAD_FOLDER'], image_filename)
            image_file.save(image_path)

            update_data['image_path'] = os.path.join('uploads', image_filename).replace('\\', '/')

        redis_client.hset(post_key, mapping=update_data)

        flash('Post/Note updated successfully!')
        return redirect(url_for('index'))

    return render_template('edit.html', post={k.decode('utf-8'): v.decode('utf-8') for k, v in post.items()})

@app.route('/delete/<post_id>', methods=['POST'])
@login_required
def delete(post_id):
    """Delete a post/note."""
    redis_client.delete(f"post:{current_user.id}:{post_id}")
    flash('Post/Note deleted successfully!')
    return redirect(url_for('index'))

@app.route('/search', methods=['GET', 'POST'])
@login_required
def search():
    """Search for posts by tags with pagination."""
    results = []
    search_query = ''
    per_page = 5  # Number of results to display per page
    page = request.args.get('page', 1, type=int)  # Get current page, default to 1

    if request.method == 'POST':
        search_query = request.form['query'].strip()
        if search_query:
            # Loop through posts and filter by tags
            for key in redis_client.scan_iter(f"post:{current_user.id}:*"):
                post = redis_client.hgetall(key)
                tags = post.get(b'tags', b'').decode('utf-8').lower()
                if search_query.lower() in tags:
                    results.append({k.decode('utf-8'): v.decode('utf-8') for k, v in post.items()})

            # Paginate results
            total_results = len(results)
            start = (page - 1) * per_page
            end = start + per_page
            paginated_results = results[start:end]
        else:
            total_results = 0
            paginated_results = []

        if not paginated_results:
            flash('No posts found with the given tags.', 'warning')
    else:
        total_results = 0
        paginated_results = []

    return render_template('search.html', 
                           results=paginated_results, 
                           query=search_query, 
                           total_results=total_results, 
                           per_page=per_page, 
                           page=page)


@app.route('/about')
def about():
    """Render the About page."""
    return render_template('about.html')

@app.route('/contact')
def contact():
    """Render the Contact page."""
    return render_template('contact.html')

@app.route('/profile')
@login_required
def profile():
    """Render the user profile page."""
    return render_template('profile.html', user=current_user)

@app.route('/post/<post_id>', methods=['GET'])
@login_required
def view_post(post_id):
    post_key = f"post:{current_user.id}:{post_id}"
    post = redis_client.hgetall(post_key)
    
    if not post:
        abort(404)

    post_data = {k.decode('utf-8'): v.decode('utf-8') for k, v in post.items()}
    post_id_extracted = post_key.split(':')[-1]
    post_data['_id'] = post_id_extracted
    
    if post_data.get('user_id') != str(current_user.id):
        abort(403)

    return render_template('view_post.html', post=post_data)


# Run the application
if __name__ == '__main__':
    app.run(debug=True)
