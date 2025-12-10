import logging
from django.shortcuts import render, redirect
from django.urls import reverse

logger = logging.getLogger(__name__)

class CustomSecurityMiddleware:
    """
    Middleware для:
    1. Ховання внутрішніх помилок користувачу.
    2. Захисту сторінки /secure.
    """
    def __init__(self, get_response):
        self.get_response = get_response

    def __call__(self, request):
        try:
            # Захист сторінки /secure
            if request.path.startswith('/secure'):
                if not request.user.is_authenticated:
                    return redirect(reverse('login'))  

            response = self.get_response(request)
        except Exception as e:
            # Логування помилки
            logger.exception("Internal server error")
            # Безпечне повідомлення користувачу
            return render(request, '500_safe.html', status=500)

        return response