import jwt
from rest_framework import status
from rest_framework.exceptions import AuthenticationFailed, PermissionDenied
from rest_framework.generics import get_object_or_404
from rest_framework.response import Response
from rest_framework.views import APIView
from django.http import Http404
from sklearn.metrics.pairwise import cosine_similarity
from sklearn.feature_extraction.text import CountVectorizer
from django.contrib.auth import get_user_model

from .models import Article
from .serializers import ArticleSerializer, ArticleStatusUpdateSerializer
from users.models import User
import spacy

nlp = spacy.load('en_core_web_sm')


class CreateArticle(APIView):
    def post(self, request):
        token = request.COOKIES.get('jwt')

        if not token:
            raise AuthenticationFailed('Unauthenticated!')

        try:
            payload = jwt.decode(token, 'secret', algorithms=['HS256'])
        except jwt.ExpiredSignatureError:
            raise AuthenticationFailed('Unauthenticated!')

        author_id = payload['id']
        author_name = get_user_model().objects.get(id=author_id).name

        serializer = ArticleSerializer(data=request.data)
        serializer.is_valid(raise_exception=True)
        serializer.save(author_id=author_id, author_name=author_name)

        return Response(serializer.data, status=status.HTTP_201_CREATED)


class ListArticles(APIView):
    def get(self, request):
        all_articles = Article.objects.all()
        pending_articles = []
        completed_articles = []

        for article in all_articles:
            if article.is_completed:
                completed_articles.append(article)
            else:
                pending_articles.append(article)

        sorted_pending_articles = self.merge_sort(pending_articles)
        serializer = ArticleSerializer(sorted_pending_articles, many=True)
        return Response(serializer.data)

    def merge_sort(self, articles):
        if len(articles) <= 1:
            return articles

        mid = len(articles) // 2
        left = self.merge_sort(articles[:mid])
        right = self.merge_sort(articles[mid:])

        return self.merge(left, right)

    def merge(self, left, right):
        result = []
        i = j = 0

        while i < len(left) and j < len(right):
            if left[i].vote > right[j].vote:
                result.append(left[i])
                i += 1
            else:
                result.append(right[j])
                j += 1

        result.extend(left[i:])
        result.extend(right[j:])
        return result


class RetrieveArticle(APIView):
    def get(self, request, article_id):
        article = self.get_article(article_id)
        serializer = ArticleSerializer(article)
        return Response(serializer.data)

    def get_article(self, article_id):
        article = get_object_or_404(Article, pk=article_id)
        return article


class SimilarArticles(APIView):
    def get(self, request, article_id):
        article = self.get_article(article_id)
        similar_articles = self.get_similar_articles(article)
        serializer = ArticleSerializer(similar_articles, many=True)
        return Response(serializer.data)

    def get_article(self, article_id):
        article = get_object_or_404(Article, pk=article_id)
        return article

    def get_similar_articles(self, article, num_suggestions=4):
        all_articles = Article.objects.exclude(id=article.id)

        # Combine the titles and contents of all articles
        all_text = [art.title + " " + art.content for art in all_articles]

        # Use spaCy for tokenization and similarity calculation
        article_text = article.title + " " + article.content
        article_doc = nlp(article_text)
        all_docs = [nlp(text) for text in all_text]

        # Calculate similarity scores using spaCy's similarity method
        similarities = [article_doc.similarity(doc) for doc in all_docs]

        # Get the indices of top similar articles
        similar_indices = sorted(range(len(similarities)), key=lambda i: similarities[i], reverse=True)[
                          :num_suggestions]

        similar_articles = [all_articles[index] for index in similar_indices]
        return similar_articles


class DeleteArticle(APIView):
    def delete(self, request, article_id):
        token = request.COOKIES.get('jwt')

        if not token:
            raise AuthenticationFailed('Unauthenticated!')

        try:
            payload = jwt.decode(token, 'secret', algorithms=['HS256'])
        except jwt.ExpiredSignatureError:
            raise AuthenticationFailed('Unauthenticated!')

        try:
            article = Article.objects.get(pk=article_id)
        except Article.DoesNotExist:
            raise Http404

        user_id = payload.get('id')
        user = User.objects.get(pk=user_id)

        if user != article.author and not user.is_admin:
            raise PermissionDenied('You do not have permission to delete this article.')

        article.delete()

        return Response({"message": "Article deleted successfully."}, status=status.HTTP_204_NO_CONTENT)


class VoteArticle(APIView):
    def post(self, request, article_id):
        token = request.COOKIES.get('jwt')

        if not token:
            raise AuthenticationFailed('Unauthenticated!')

        try:
            payload = jwt.decode(token, 'secret', algorithms=['HS256'])
        except jwt.ExpiredSignatureError:
            raise AuthenticationFailed('Unauthenticated!')

        try:
            article = Article.objects.get(pk=article_id)
        except Article.DoesNotExist:
            raise Http404

        vote_type = request.data.get('vote_type')

        # Store user information
        user_id = payload['id']
        user = get_user_model().objects.get(pk=user_id)

        if vote_type == 'upvote':
            # Remove user from downvoted_by
            article.downvoted_by.remove(user)
            # Add user to upvoted_by
            article.upvoted_by.add(user)
            article.vote += 1
        elif vote_type == 'downvote':
            # Remove user from upvoted_by
            article.upvoted_by.remove(user)
            # Add user to downvoted_by
            article.downvoted_by.add(user)
            article.vote -= 1
        else:
            return Response({'error': 'Invalid vote_type'}, status=status.HTTP_400_BAD_REQUEST)

        article.save()

        return Response(status=status.HTTP_200_OK)


class ArticleStatusUpdate(APIView):
    def patch(self, request, article_id):
        token = request.COOKIES.get('jwt')

        if not token:
            raise AuthenticationFailed()

        try:
            payload = jwt.decode(token, 'secret', algorithms=['HS256'])
        except jwt.ExpiredSignatureError:
            raise AuthenticationFailed()

        user = get_user_model().objects.filter(pk=payload['id']).first()

        if not user or not user.is_admin:
            raise PermissionDenied()

        try:
            article = Article.objects.get(pk=article_id)
        except Article.DoesNotExist:
            raise Http404

        serializer = ArticleStatusUpdateSerializer(data=request.data)
        serializer.is_valid(raise_exception=True)

        is_completed = serializer.validated_data['is_completed']
        article.is_completed = is_completed
        article.save()

        return Response({'is_completed': is_completed}, status=status.HTTP_200_OK)


class CompletedArticleList(APIView):
    def get(self, request):
        completed_articles = Article.objects.filter(is_completed=True)
        serializer = ArticleSerializer(completed_articles, many=True)
        return Response(serializer.data)
