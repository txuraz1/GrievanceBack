from django.contrib import admin
from django.urls import path
from .views import ListArticles, RetrieveArticle, CreateArticle, DeleteArticle, VoteArticle, SimilarArticles, \
    ArticleStatusUpdate, CompletedArticleList

urlpatterns = [
    path('articles/', ListArticles.as_view(), name='list_articles'),
    path('articles/create/', CreateArticle.as_view(), name='create_article'),
    path('articles/<int:article_id>/delete/', DeleteArticle.as_view(), name='delete_article'),
    path('articles/<int:article_id>/vote/', VoteArticle.as_view(), name='vote_article'),
    path('articles/<int:article_id>/', RetrieveArticle.as_view(), name='retrieve_article'),
    path('articles/<int:article_id>/similar/', SimilarArticles.as_view(), name='similar_articles'),
    path('articles/<int:article_id>/status/', ArticleStatusUpdate.as_view(), name='update-article-status'),
    path('articles/completed-articles/', CompletedArticleList.as_view(), name='completed_articles'),

]