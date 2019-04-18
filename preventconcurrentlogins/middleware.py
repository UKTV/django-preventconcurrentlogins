from django.contrib.sessions.models import Session
from django.conf import settings
from importlib import import_module

from preventconcurrentlogins.models import Visitor

engine = import_module(settings.SESSION_ENGINE)

class PreventConcurrentLoginsMiddleware(object):
    """
    Django middleware that prevents multiple concurrent logins..
    Adapted from http://stackoverflow.com/a/1814797 and https://gist.github.com/peterdemin/5829440
    """
    def do_check(self, request):
        if hasattr(request, 'user') and request.user.is_authenticated():
            if not request.session.session_key:
                request.session.save()
            key_from_cookie = request.session.session_key
            if hasattr(request.user, 'visitor'):
                session_key_in_visitor_db = request.user.visitor.session_key
                if session_key_in_visitor_db != key_from_cookie:
                    # Delete the Session object from database and cache
                    engine.SessionStore(session_key_in_visitor_db).delete()
                    request.user.visitor.session_key = key_from_cookie
                    request.user.visitor.save()
            else:
                Visitor.objects.create(
                    user=request.user,
                    session_key=key_from_cookie
                )

    def process_request(self, request):
        self.do_check(request)

    def process_response(self, request, response):
        self.do_check(request)

        return response
