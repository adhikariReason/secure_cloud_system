from django.urls import include, path

urlpatterns = [
    path("", include("files.urls")),
]
