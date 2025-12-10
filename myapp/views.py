from django.shortcuts import render, redirect
from django.contrib.auth import authenticate, login, logout
from django.contrib.auth.decorators import login_required
from django.utils.html import escape  # Для захисту від XSS
import re
import bleach  # Для більш глибокого очищення HTML
import logging  # Для логування внутрішніх помилок
from django.utils import timezone
import datetime

#bleach — це стороння бібліотека Python для очищення HTML і захисту від XSS (Cross-Site Scripting). 
#Вона дозволяє безпечно видаляти 
#або дозволяти лише певні HTML-теги та атрибути, які не можуть виконати шкідливий JavaScript.

# Сторінка логіну
def login_page(request):
    return render(request, 'login.html')

# Обробка форми логіну 
def auth_user(request):
    errors = []

    try:
        # Ініціалізація лічильника невдалих спроб у сесії
        if 'login_attempts' not in request.session:
            request.session['login_attempts'] = 0

        # Перевіряємо, чи є активне блокування входу
        block_until = request.session.get('block_until')
        if block_until:
            block_time = datetime.datetime.fromisoformat(block_until)
            now = timezone.now()

            if now < block_time:
                remaining = (block_time - now).seconds
                errors.append(f"Ви заблоковані. Спробуйте через {remaining} секунд.")
                return render(request, 'login.html', {'errors': errors})
            else:
                # Блокування минуло — скидаємо
                request.session['login_attempts'] = 0
                request.session['block_until'] = None

        # Блокування після 3 помилок
        if request.session['login_attempts'] >= 3:
            # Якщо дійшли сюди — значить блок ще не був створений → створи на 60 секунд
            block_time = timezone.now() + datetime.timedelta(seconds=60)
            request.session['block_until'] = block_time.isoformat()
            errors.append("Ви перевищили 3 спроби входу. Спробуйте пізніше.")
            return render(request, 'login.html', {'errors': errors})

        if request.method == "POST":
            # Отримуємо дані
            email = request.POST.get('email', '').strip()
            password = request.POST.get('password', '').strip()

            # Захист від XSS
            email = escape(email)
            password = escape(password)

            # Додаткове очищення HTML (якщо вставив HTML/JS)
            email = bleach.clean(email)
            password = bleach.clean(password)

            # Перевірка на порожні поля
            if not email:
                errors.append("Введіть email")
            if not password:
                errors.append("Введіть пароль")

            # Перевірка формату email
            email_regex = r'^[\w\.-]+@[\w\.-]+\.\w+$'
            if email and not re.match(email_regex, email):
                errors.append("Введіть коректний email")

            # Якщо немає помилок, пробуємо авторизувати
            if not errors:
                user = authenticate(request, username=email, password=password)
                if user is not None:
                    login(request, user)
                    # Скидаємо лічильник при успішному вході
                    request.session['login_attempts'] = 0
                    request.session['block_until'] = None
                    return redirect('/secure')
                else:
                    errors.append("Невірний логін або пароль")
                    # Збільшуємо лічильник невдалих спроб
                    request.session['login_attempts'] += 1

                    # Якщо це третя спроба → включаємо блок на 1 хвилину
                    if request.session['login_attempts'] >= 3:
                        block_time = timezone.now() + datetime.timedelta(seconds=60)
                        request.session['block_until'] = block_time.isoformat()
                        errors.append("Ви заблоковані на 1 хвилину.")
                        return render(request, 'login.html', {'errors': errors})

    except Exception:
        # Логування помилки в бекенд (не показуємо користувачу)
        import logging
        logging.exception("Помилка під час авторизації")
        errors.append("Сталася помилка. Спробуйте пізніше.")

    return render(request, 'login.html', {'errors': errors})

# Захищена сторінка
@login_required(login_url='/login/')
def secure_page(request):
    return render(request, 'secure.html', {'user': request.user})

# Вихід із системи
def logout_view(request):
    logout(request)  # Django очищає сесію
    return redirect('/login/')