from django.urls import path

from . import views

urlpatterns = [
    path("", views.file_list, name="file_list"),
    path("shared/", views.shared_list, name="shared_list"),
    path("audit/", views.audit_log, name="audit_log"),
    path("register/", views.register, name="register"),
    path("login/", views.login_view, name="login"),
    path("logout/", views.logout_view, name="logout"),
    path("upload/", views.upload, name="upload"),
    path("files/<uuid:file_id>/", views.detail, name="detail"),
    path("files/<uuid:file_id>/download/", views.download, name="download"),
    path("files/<uuid:file_id>/verify/", views.verify, name="verify"),
    path("files/<uuid:file_id>/share/", views.share, name="share"),
    path("files/<uuid:file_id>/unshare/<int:share_id>/", views.unshare, name="unshare"),
    path("files/<uuid:file_id>/delete/", views.delete, name="delete"),
]
