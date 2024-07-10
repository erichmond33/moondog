from django.urls import path

from . import views


urlpatterns = [
    path("", views.index, name="index"),
    path("landing", views.landing, name="landing"),
    path("login", views.login_view, name="login"),
    path("logout", views.logout_view, name="logout"),
    path('profile', views.current_user_profile, name='current_user_profile'),
    path('profile/<str:username>/', views.profile, name='profile'),
    path('register', views.register, name='register'),
    # path('profile/<int:user_id>/', views.profile, name='profile_with_id'),
    path("profile", views.profile, name="profile"),
    path("feed", views.current_user_feed, name="current_user_feed"),
    path('feed/<str:username>/', views.feed, name='feed'),
    path("post/<int:post_id>/", views.post, name="post"),
    path("post/<int:post_id>/add_comment/", views.add_comment, name="add_comment"),
    path("post/<int:comment_id>/reply_comment/", views.reply_comment, name="reply_comment"),
    path("Linkfeed/post/<int:post_id>/delete_post/", views.delete_post, name='delete_post'),
    path('delete_comment/<int:comment_id>/', views.delete_comment, name='delete_comment'),
    path("post/<int:post_id>/edit/", views.edit_post, name="edit_post"),  # URL for editing a post
    path("create_post/", views.create_post, name="create_post"),
    path('like/<int:post_id>', views.like_view, name='like_post'),  # URL for liking/unliking a post
    path('followers/<str:username>/', views.followers_view, name='followers'),
    path('following/<str:username>/', views.following_view, name='following'),
    path('follow/<str:username>/', views.follow_or_unfollow, name='follow_or_unfollow'),
    path('rss/', views.rss, name='rss'),
    path('mirror-rss-feed/', views.mirror_rss_feed, name='mirror_rss_feed'),
    path('refresh-mirrored-rss-feed/', views.refresh_mirrored_rss_feed, name='refresh_mirrored_rss_feed'),
    path('landing/', views.landing, name='landing'),
    path("edit_profile/", views.edit_profile, name="edit_profile"),
    path('search-users/', views.search_users, name='search_users'),

]
         
         

