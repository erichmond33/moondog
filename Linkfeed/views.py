from sqlite3 import IntegrityError
from django.shortcuts import render, get_object_or_404, redirect
from django.http import HttpResponseRedirect, HttpResponse,HttpResponseForbidden, JsonResponse, HttpResponseBadRequest
from django.urls import reverse
from django.contrib.auth import authenticate, login, logout
from django.contrib.auth.decorators import login_required
from .models import *
from django.shortcuts import render, redirect
from django.core.paginator import Paginator, EmptyPage, PageNotAnInteger
from django.db.models import Q, Count
from django.http import Http404
import feedparser
import datetime
import dateutil.parser 
from django.db.models import Q
from datetime import datetime
import pytz
import time 
from django.db.models import Count
from django.views.decorators.http import require_GET


def index(request):
    if request.user.is_authenticated:
        return redirect('profile', username=request.user.username)
    else:
        return render(request, "Linkfeed/landingpage.html")
    
def landing(request):
    return render(request, "Linkfeed/landingpage.html")

@login_required
def current_user_profile(request):
    return profile(request, request.user.username)



def profile(request, username):
    user = User.objects.get(username=username)
    posts = Post.objects.filter(user=user)
    profile = Profile.objects.get(user=user)
    domain = profile.domain
    
    profile.link = domain
    profile.stripped_link = profile.strippedDomainLink()

    profile.following_count = profile.formatCount("following")
    profile.followers_count = profile.formatCount("followers")

    # Order posts reverse chronologically
    posts = Post.objects.filter(user=user).annotate(total_comments=Count('comments')).order_by('-timestamp')

    # Check if the user has liked each post
    for post in posts:
        post.liked = post.likes.filter(id=user.id).exists()

    return render(request, "Linkfeed/profile.html", {"posts": posts, "profile": profile})


@login_required
def current_user_feed(request):
    return feed(request, request.user.username)

     
def feed(request, username):
    # Retrieve the user object based on the username
    user = User.objects.get(username=username)
    profile = Profile.objects.get(user=user)

    # Retrieve the IDs of Linkfeed that the user is following
    following_ids = profile.following.all().values_list('id', flat=True)

    # Retrieve posts from the Linkfeed that the user is following and not imported RSS feed posts
    posts = Post.objects.filter((Q(user__id__in=following_ids))).annotate(total_comments=Count('comments')).order_by('-timestamp')

    # Check if the user has liked each post
    for post in posts:
        post.liked = post.likes.filter(id=user.id).exists()

    # Check if the current user has liked each post
    for post in posts:
        post.liked = post.likes.filter(id=request.user.id).exists()
    return render(request, 'Linkfeed/feed.html', {"posts" : posts, "profile" : profile})


def login_view(request):
    if request.method == "POST":
        username = request.POST["username"]
        password = request.POST["password"]
        user = authenticate(request, username=username, password=password)
        if user is not None:
            login(request, user)
            # Pass the authentication token to the session
            # request.session['auth_token'] = request.session.session_key
            # return HttpResponseRedirect(reverse("index"))
            return redirect('profile', username=username)
        else:
            return render(request, "Linkfeed/login.html", {
                "message": "Invalid credentials."
            })
    return render(request, "Linkfeed/login.html")



from django.db import IntegrityError
import logging

logger = logging.getLogger(__name__)

def register(request):
    if request.method == "POST":
        username = request.POST.get("username")
        display_name = username
        link = request.POST.get("link")
        stripped_link = link.split('//')[-1].split('/')[0] # Stripped link
        username = stripped_link
        email = request.POST.get("email")
        password = request.POST.get("password")
        confirmation = request.POST.get("confirmation")

        # Ensure password matches confirmation
        if password != confirmation:
            return render(request, "Linkfeed/register.html", {
                "message": "Passwords must match."
            })

        try:
            username_taken = True
            while username_taken:
                try:
                    user = User.objects.get(username=username)
                    if user:
                        # Increment username i.e. username1, username2, username3
                        username = f"{stripped_link}{int(username[-1]) + 1 if username[-1].isdigit() else 1}"

                except User.DoesNotExist:
                    username_taken = False

            # Attempt to create new user
            user = User.objects.create_user(username, email, password)

            # Create a Profile instance with the link
            profile = Profile.objects.create(user=user, display_name=display_name, domain=link)

            # Log in the user
            login(request, user)
            return HttpResponseRedirect(reverse("index"))
        except IntegrityError as e:
            if 'unique constraint' in str(e).lower() and 'username' in str(e).lower():
                # Username already exists
                return render(request, "Linkfeed/register.html", {
                    "message": "Username already exists."
                })
            else:
                # Other IntegrityError, log and render generic error message
                logger.error("IntegrityError occurred during user registration: %s", e)
                return render(request, "Linkfeed/register.html", {
                    "message": "An error occurred during registration. Please try again later."
                })

    else:
        return render(request, "Linkfeed/register.html")

def logout_view(request):
    logout(request)
    return render(request, "Linkfeed/login.html", {
        "message": "Logged out."
    })

def post(request, post_id):
    try:
        stuff = get_object_or_404(Post, id=post_id)
        # Get the profile of the user who created the post
        profile = Profile.objects.get(user=stuff.user)
        total_likes = stuff.total_likes()
        liked = False
        if stuff.likes.filter(id=request.user.id).exists():
            liked = True
        post = get_object_or_404(Post, id=post_id)
        comments = Comment.objects.filter(post=post, parent_comment=None)  # Fetch comments associated with the post
        add_level(comments)
        return render(request, "Linkfeed/post.html", {"post": post, "comments": comments, 'stuff': stuff, 'total_likes': total_likes, 'liked': liked, 'profile': profile})
    except Http404:
        return HttpResponse("404 - Post Not Found", status=404)
        
def add_level(comments, level=0):
    for comment in comments:
        comment.level = level
        print(level)
        add_level(comment.replies.all(), level + 1)

@login_required
def add_comment(request, post_id):
    if request.method == "POST":
        post = get_object_or_404(Post, id=post_id)
        comment_body = request.POST.get("body")
        # make suer the body doesn't have a tab at the begginingg?
        comment_body = comment_body.strip()
        # Create a new comment object and save it to the database
        comment = Comment.objects.create(user=request.user, post=post, body=comment_body)
        # Redirect to the post detail page after adding the comment
        return redirect("post", post_id=post_id)

def reply_comment(request, comment_id):
    if request.method == "POST":
        parent_comment = get_object_or_404(Comment, id=comment_id)
        post = parent_comment.post
        comment_body = request.POST.get("body")
        # Create a new comment object and save it to the database
        comment = Comment.objects.create(user=request.user, post=post, body=comment_body, parent_comment=parent_comment)
        # Redirect to the post detail page after adding the comment
        return redirect("post", post_id=post.id)

from django.shortcuts import redirect
from django.contrib import messages

def delete_comment(request, comment_id):
    if request.method == "POST" or request.method == "GET":
        comment = get_object_or_404(Comment, id=comment_id)
        # Check if the user is authenticated
        if request.user.is_authenticated:
            # Check if the user is the owner of the comment or the owner of the post
            if comment.user == request.user or comment.post.user == request.user:
                comment.delete()
                # Redirect to the previous page
                return redirect(request.META.get('HTTP_REFERER', '/'))
            else:
                # Handle unauthorized deletion
                messages.error(request, 'You are not authorized to delete this comment.')
        else:
            # Handle authentication error
            messages.error(request, 'You must be logged in to delete a comment.')
    # If the request method is not POST or deletion fails, redirect to the previous page
    return redirect(request.META.get('HTTP_REFERER', '/'))





def delete_post(request, post_id):
    if request.method == "POST":
        post = get_object_or_404(Post, id=post_id)
        # Check if the user is authenticated and is the owner of the post
        if request.user.is_authenticated and post.user == request.user:
            post.delete()
            # Redirect back to the same page
            return HttpResponseRedirect(request.META.get('HTTP_REFERER', reverse('profile')))
        else:
            # Handle unauthorized deletion
            return HttpResponseForbidden("You are not authorized to delete this post.")

def edit_post(request, post_id):
    if request.method == "POST":
        post = get_object_or_404(Post, id=post_id)
        # Check if the user is authenticated and is the owner of the post
        if request.user.is_authenticated and post.user == request.user:
            # Update the post title and body with the new values
            post.title = request.POST.get("post_title")
            post.body = request.POST.get("post_body")
            post.save()
            # Redirect back to the post detail page after editing the post
            return redirect("post", post_id=post_id)
        else:
            # Handle unauthorized edits
            return HttpResponseForbidden("You are not authorized to edit this post.")
    # Handle other HTTP methods if necessary


@login_required  # Ensure the user is logged in 
def edit_profile(request):
    if request.method == "POST":
        # Get the current user's profile instance
        profile = get_object_or_404(Profile, user=request.user)

        # Update the link
        new_link = request.POST.get('link')
        if new_link:
            profile.domain = new_link
            profile.save()

        # Update the display_name
        new_display_name = request.POST.get('display_name')
        if new_display_name:
            profile.display_name = new_display_name
            profile.save()

        # Update the username
        new_username = request.POST.get('username')
        if new_username:
            # Check if the new username is already taken
            if User.objects.filter(username=new_username).exclude(pk=request.user.pk).exists():
                # Handle the case where the username is already taken
                # You can display an error message or take any other appropriate action
                error_message = "The username is already taken. Please choose a different one."
                # Pass the error message to the template context
                context = {'error_message': error_message}
                return HttpResponseBadRequest("The username is already taken. Please choose a different one.")
            else:
                request.user.username = new_username
                request.user.save()

        # Redirect to the profile page after editing
        return redirect('profile') 
    else:
        # Handle GET request (display edit profile form)
        return HttpResponseForbidden("You are not authorized to edit this profile.")

def create_post(request):
    if request.method == "POST":
        title = request.POST.get('title')
        body = request.POST.get('body')
        # Create a new post
        new_post = Post.objects.create(user=request.user, title=title, body=body)

        # Redirect to the profile page after creating the post
        return HttpResponseRedirect(reverse("profile"))
    else:
        return render(request, "Linkfeed/create_post.html")
    
@login_required
def like_view(request, post_id):
    if request.method == 'POST':
        post = Post.objects.get(id=post_id)
        user = request.user
        if user in post.likes.all():
            post.likes.remove(user)
        else:
            post.likes.add(user)
        return JsonResponse({'total_likes': post.total_likes()})
    else:
        return HttpResponseBadRequest("Invalid request method")


@login_required
def followers_view(request, username):
    profile = get_object_or_404(Profile, user__username=username)
    followers = profile.follower.all()
    return render(request, 'Linkfeed/followers.html', {'followers': followers, "profile" : profile})


@login_required
def following_view(request, username):
    profile = get_object_or_404(Profile, user__username=username)
    # Get the Linkfeed followed by the user
    following = profile.following.all()
    return render(request, 'Linkfeed/following.html', {'following': following, "profile" : profile})
    
@login_required
def follow_or_unfollow(request, username):
    # Retrieve the profile of the user to follow
    profile_to_follow = Profile.objects.get(user__username=username)
    profile = Profile.objects.get(user=request.user)

    # Check if the logged-in user is already following the profile
    if request.user in profile_to_follow.follower.all():
        # User is already following, so unfollow
        profile_to_follow.follower.remove(request.user)
        profile.following.remove(profile_to_follow.user)
    else:
        # User is not following, so follow
        profile_to_follow.follower.add(request.user)
        profile.following.add(profile_to_follow.user)

    # Render the same page after following or unfollowing
    return HttpResponseRedirect(request.META.get('HTTP_REFERER', reverse('profile')))

def parse_timestamp(entry):
    timestamp_str = {
                'published': entry.get('published'),
                'pubDate': entry.get('pubDate'),
                'dc:date': entry.get('dc:date'),
                'date' : entry.get('date'),
                'atom:published': entry.get('atom:published'),
                'dc:created': entry.get('dc:created')
            }
    formats = [
        '%Y-%m-%dT%H:%M:%S%z',  # Original format
        '%a, %d %b %Y %H:%M:%S %Z',  # pubDate format
        '%Y-%m-%d'  # Added for parsing only dates
    ]

    if isinstance(timestamp_str, str):
        # Direct Parsing Attempt for strings:
        for fmt in formats:
            try:
                # Attempt to parse as datetime first 
                if fmt == '%Y-%m-%dT%H:%M:%S%z':
                    return datetime.strptime(timestamp_str, fmt)
                elif fmt == '%Y-%m-%d':
                    return datetime.strptime(timestamp_str, fmt).date()
                else:
                    return dateutil.parser.parse(timestamp_str) 
            except ValueError:
                continue  # Try other formats

    elif isinstance(timestamp_str, dict):
        # Iterate over potential field names (if direct parsing failed)
        for field_name in timestamp_str:
            timestamp = timestamp_str.get(field_name)
            if timestamp:
                for fmt in formats:
                    try:
                        # Attempt to parse as datetime first 
                        if fmt == '%Y-%m-%dT%H:%M:%S%z':
                            return datetime.strptime(timestamp, fmt)
                        elif fmt == '%Y-%m-%d':
                            return datetime.strptime(timestamp, fmt).date()
                        else:
                            return dateutil.parser.parse(timestamp) 
                    except ValueError:
                        continue  # Try other formats

    return None  # Parsing unsuccessful

@login_required
def rss(request):
    profile = Profile.objects.get(user=request.user)
    return render(request, 'Linkfeed/rss.html', {'profile' : profile})

def mirror_rss_feed(request):
    if request.method == 'POST':
        rss_link = request.POST.get('link')
        user = request.user

        if RSSFeed.objects.filter(user=user).exists():
            return redirect('profile')

        rss_feed = RSSFeed.objects.create(user=user, link=rss_link)
        rss_feed = feedparser.parse(rss_feed.link)
        
        for entry in reversed(rss_feed.entries):
            post_timestamp = None
            title = entry.get('title', 'No Title')
            body = entry.get('link', 'No Link')
                
            post_timestamp = parse_timestamp(entry)
            if post_timestamp is None:
                post_timestamp = datetime.now()
            
            Post.objects.create(user=user, title=title, body=body, is_rss_feed_post=True, timestamp=post_timestamp)

    return redirect('profile')

def refresh_mirrored_rss_feed_view(request):
    user = request.user
    rss_feed = RSSFeed.objects.filter(user=user).first()
    refresh_mirrored_rss_feed(user, rss_feed)

    return redirect('profile')

def refresh_mirrored_rss_feed(user, rss_feed):
    if rss_feed:
        feed = feedparser.parse(rss_feed.link)

        for entry in reversed(feed.entries):
            title = entry.get('title', 'No Title')
            body = entry.get('link', 'No Link')

            post_timestamp = parse_timestamp(entry)
            if post_timestamp is None:
                post_timestamp = datetime.now()

            if not Post.objects.filter(user=user, title=title, body=body, is_rss_feed_post=True).exists():
                Post.objects.create(
                    user=user,
                    title=title,
                    body=body,
                    is_rss_feed_post=True,
                    timestamp=post_timestamp
                )
    return

def landing(request):
    return render(request, 'Linkfeed/landingpage.html')

def search_users(request):
    if request.method == 'GET':
        query = request.GET.get('query', '')
        users = User.objects.filter(username__icontains=query)
        user_list = [user.username for user in users]
        return JsonResponse({'users': user_list})
    else:
        query = request.GET.get('query', '')
        users = User.objects.filter(username__icontains=query)
        user_list = [user.username for user in users]
        return render(request, 'profile.html', {'users': user_list})