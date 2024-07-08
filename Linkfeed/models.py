from django.contrib.auth.models import AbstractUser
from django.db import models
from django.db.models.signals import post_save
from django.dispatch import receiver

class User(AbstractUser):
    pass

class RSSFeed(models.Model):
    user = models.ForeignKey(User, on_delete=models.CASCADE)
    link = models.URLField()

    def __str__(self):
        return f"{self.user.username}'s RSS Feed: {self.link}"

class ImportedRSSFeed(models.Model):
    user = models.ForeignKey(User, on_delete=models.CASCADE)
    link = models.URLField()

    def __str__(self):
        return f"Imported RSS Feed for {self.user.username}: {self.link}"
    
from django.db import models
import datetime

class Post(models.Model):
    user = models.ForeignKey(User, on_delete=models.CASCADE, related_name="posts")
    title = models.CharField(blank=True, max_length=255)
    body = models.URLField(blank=True, null=True)
    likes = models.ManyToManyField(User, related_name="blog_posts")
    timestamp = models.DateTimeField(auto_now_add=False, null=True)
    is_rss_feed_post = models.BooleanField(default=False)
    is_imported_rss_feed_post = models.BooleanField(default=False)
    imported_rss_feed = models.ForeignKey(ImportedRSSFeed, on_delete=models.SET_NULL, null=True, blank=True, related_name="posts")
    repost_count = models.IntegerField(default=0)  # New field for repost count

    def save(self, *args, **kwargs):
        if not self.timestamp:
            self.timestamp = datetime.datetime.now()
        super(Post, self).save(*args, **kwargs)

    def total_comments(self):
        return self.comments.count()
    
    def total_likes(self):
        return self.likes.count()

    def __str__(self):
        return f"{self.id} : {self.user.username} : id={self.user.id} : {self.title} : {self.body} : {self.likes} : {self.timestamp}"

    def serialize(self):
        return {
            "id": self.id,
            "user_id": self.user.id,
            "user_name": self.user.username,
            "body": self.body,
            "likes": self.likes,
            "timestamp": self.timestamp.strftime("%b %d %Y, %I:%M %p"),
        }



class PostLike(models.Model):
    user = models.ForeignKey(User, on_delete=models.CASCADE)
    post = models.ForeignKey(Post, on_delete=models.CASCADE)

    def __tr__(self):
        return f"{self.user.username}"

class Comment(models.Model):
    user = models.ForeignKey(User, on_delete=models.CASCADE, related_name="comments")
    post = models.ForeignKey(Post, on_delete=models.CASCADE, related_name="comments")
    parent_comment = models.ForeignKey('self', on_delete=models.CASCADE, null=True, blank=True, related_name='replies')
    body = models.TextField()
    likes = models.IntegerField(default=0)
    timestamp = models.DateTimeField(auto_now_add=True)
    level = models.IntegerField(default=0)

    def __str__(self):
        return f"{self.user.username} : {self.post.title} : {self.body} : {self.timestamp}"
    
    def save(self, *args, **kwargs):
        if self.parent_comment:
            self.level = self.parent_comment.level + 1
        super().save(*args, **kwargs)

class Profile(models.Model):
    user = models.OneToOneField(User, on_delete=models.CASCADE)
    display_name = models.CharField(max_length=255, blank=True, null=True)
    follower = models.ManyToManyField(User, blank=True, related_name="follower_user")
    following = models.ManyToManyField(User, blank=True, related_name="following_user")

    def __str__(self):
        return f"{self.user.username} : Followers = {self.follower.count()}  : Following = {self.following.count()}"
    
    def formatCount(self, followers_or_following):
        if followers_or_following == "followers":
            # Retrieve the follower count
            count = self.follower.count()
        elif followers_or_following == "following":
            # Retrieve the following count
            count = self.following.count()

        # Determine the appropriate format based on the number of followers
        if count < 10:
            formatted = f"{count}"  # Three spaces for single digit numbers
        elif count < 100:
            formatted = f"{count}"  # Two spaces for two digit numbers
        elif count < 1000:
            formatted = f"{count}"  # One space for three digit numbers
        elif count < 10000:
            formatted = f"{count}"  # Exact count for 1000-9999
        elif count < 100000:
            formatted = f"{count // 1000}k"  # Thousands without decimal for 10k-99k
        elif count < 1000000:
            formatted = f"{count / 1000:.1f}k"  # Thousands with one decimal for 100k-999k
        elif count < 10000000:
            formatted = f"{count // 1000000}m"  # Millions without decimal for 1m-9m
        else:
            formatted = f"{count / 1000000:.1f}m"  # Millions with one decimal for 10m and more

        return formatted

# @receiver(post_save, sender=User)
# def create_user_profile(sender, instance, created, **kwargs):
#     if created:
#         Profile.objects.create(user=instance)

# @receiver(post_save, sender=User)
# def save_user_profile(sender, instance, **kwargs):
#     instance.profile.save()


class UserCSS(models.Model):
    user = models.ForeignKey(User, on_delete=models.CASCADE)
    link = models.URLField()  # Store the CSS content directly

    def __str__(self):
        return f"Custom CSS Style for {self.user.username}"

from django.db import models
from django.contrib.auth import get_user_model  # Import the correct function

class AllowedDomain(models.Model):
    user = models.OneToOneField(User, on_delete=models.CASCADE)
    domain = models.URLField(blank=True, null=True)

    def __str__(self):
        return f"{self.user.username} - {self.domain}"
    
    def strippedDomainLink(self):
        return self.domain.replace("http://", "").replace("https://", "").strip("/")

