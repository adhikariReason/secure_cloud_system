from django.urls import path

from . import views

urlpatterns = [
    path("", views.file_list, name="file_list"),
    path("register/", views.register, name="register"),
    path("upload/", views.upload, name="upload"),
    path("download/<uuid:file_id>/", views.download, name="download"),
    path("delete/<uuid:file_id>/", views.delete, name="delete"),
]
