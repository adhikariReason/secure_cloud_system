from django.urls import include, path

urlpatterns = [
    path("accounts/", include("django.contrib.auth.urls")),  # login / logout
    path("", include("files.urls")),
]
