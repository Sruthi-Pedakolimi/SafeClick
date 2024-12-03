from django.shortcuts import redirect
from django.urls import path
from . import views  # Import views from your app

urlpatterns = [
    path('', views.home, name='home'),
    path('classify/', views.classify_url, name='classify_url'), 
    # path('', lambda request: redirect('classify/')),# Define classify endpoint

]
from django.http import JsonResponse

def classify_url(request):
    return JsonResponse({'message': 'Classify URL works!'})


