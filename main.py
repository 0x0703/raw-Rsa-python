"""
RSA Encryption/Decryption Application
Графический интерфейс для работы с RSA шифрованием
"""

import tkinter as tk
from tkinter import ttk, messagebox, filedialog
import threading
from rsa_core import (
    generate_keypair,
    encrypt_message,
    decrypt_message,
    key_to_string,
    string_to_key,
    keys_to_pem,
    pem_to_keys,
    is_pem_format,
    _ensure_cryptography
)


class RSAApp:
    """Главный класс приложения RSA"""

    def __init__(self, root):
        self.root = root
        self.root.title("RSA Encryption")
        self.root.geometry("900x700")
        self.root.minsize(800, 600)

        # Ключи
        self.public_key = None
        self.private_key = None

        # UI элементы (инициализируются в create_ui)
        self.notebook = None
        self.key_size_var = None
        self.key_format_var = None
        self.gen_status = None
        self.public_key_text = None
        self.private_key_text = None
        self.encrypt_input = None
        self.encrypt_output = None
        self.decrypt_input = None
        self.decrypt_output = None
        self.status_label = None

        # Цветовая схема - тёмная тема с акцентами
        self.colors = {
            'bg_dark': '#0d1117',
            'bg_medium': '#161b22',
            'bg_light': '#21262d',
            'accent': '#58a6ff',
            'accent_hover': '#79c0ff',
            'success': '#3fb950',
            'warning': '#d29922',
            'error': '#f85149',
            'text': '#c9d1d9',
            'text_muted': '#8b949e',
            'border': '#30363d'
        }

        self._setup_styles()
        self._create_ui()

    def _setup_styles(self):
        """Настройка стилей виджетов"""
        self.root.configure(bg=self.colors['bg_dark'])

        style = ttk.Style()
        style.theme_use('clam')

        # Основной стиль фрейма
        style.configure('Main.TFrame', background=self.colors['bg_dark'])
        style.configure('Card.TFrame', background=self.colors['bg_medium'])

        # Стиль заголовков
        style.configure('Title.TLabel',
                        background=self.colors['bg_dark'],
                        foreground=self.colors['accent'],
                        font=('Segoe UI', 24, 'bold'))

        style.configure('Subtitle.TLabel',
                        background=self.colors['bg_dark'],
                        foreground=self.colors['text_muted'],
                        font=('Segoe UI', 10))

        style.configure('Header.TLabel',
                        background=self.colors['bg_medium'],
                        foreground=self.colors['text'],
                        font=('Segoe UI', 12, 'bold'))

        style.configure('Info.TLabel',
                        background=self.colors['bg_medium'],
                        foreground=self.colors['text_muted'],
                        font=('Segoe UI', 9))

        # Стиль кнопок
        style.configure('Action.TButton',
                        background=self.colors['accent'],
                        foreground='white',
                        font=('Segoe UI', 10, 'bold'),
                        padding=(20, 10))

        style.map('Action.TButton',
                  background=[('active', self.colors['accent_hover'])])

        style.configure('Secondary.TButton',
                        background=self.colors['bg_light'],
                        foreground=self.colors['text'],
                        font=('Segoe UI', 10),
                        padding=(15, 8))

        # Notebook (вкладки)
        style.configure('TNotebook',
                        background=self.colors['bg_dark'],
                        borderwidth=0)

        style.configure('TNotebook.Tab',
                        background=self.colors['bg_light'],
                        foreground=self.colors['text_muted'],
                        padding=(20, 10),
                        font=('Segoe UI', 10))

        style.map('TNotebook.Tab',
                  background=[('selected', self.colors['bg_medium'])],
                  foreground=[('selected', self.colors['accent'])])

        # Комбобокс
        style.configure('TCombobox',
                        fieldbackground=self.colors['bg_light'],
                        background=self.colors['bg_light'],
                        foreground=self.colors['text'])

    def _create_ui(self):
        """Создание пользовательского интерфейса"""
        # Главный контейнер
        main_frame = ttk.Frame(self.root, style='Main.TFrame')
        main_frame.pack(fill=tk.BOTH, expand=True, padx=20, pady=20)

        # Заголовок
        header_frame = ttk.Frame(main_frame, style='Main.TFrame')
        header_frame.pack(fill=tk.X, pady=(0, 20))

        title_label = ttk.Label(header_frame,
                                text="Raw RSA Cryptography",
                                style='Title.TLabel')
        title_label.pack(anchor=tk.W)

        subtitle_label = ttk.Label(header_frame,
                                   text="Asymmetric message encryption",
                                   style='Subtitle.TLabel')
        subtitle_label.pack(anchor=tk.W)

        # Notebook для вкладок
        self.notebook = ttk.Notebook(main_frame)
        self.notebook.pack(fill=tk.BOTH, expand=True)

        # Создаём вкладки
        self._create_keys_tab()
        self._create_encrypt_tab()
        self._create_decrypt_tab()

        # Статус бар
        self._create_status_bar(main_frame)

    def _create_keys_tab(self):
        """Вкладка генерации ключей"""
        tab = ttk.Frame(self.notebook, style='Main.TFrame')
        self.notebook.add(tab, text="  Keys  ")

        # Карточка генерации
        gen_card = self._create_card(tab, "Key Generation")
        gen_card.pack(fill=tk.X, pady=(10, 10))

        # Выбор размера ключа
        size_frame = tk.Frame(gen_card.content, bg=self.colors['bg_medium'])
        size_frame.pack(fill=tk.X, pady=10)

        size_label = ttk.Label(size_frame, text="Key size:",
                               style='Info.TLabel')
        size_label.pack(side=tk.LEFT)

        self.key_size_var = tk.StringVar(value="1024")
        size_combo = ttk.Combobox(size_frame, textvariable=self.key_size_var,
                                  values=["512", "1024", "2048"],
                                  state='readonly', width=10)
        size_combo.pack(side=tk.LEFT, padx=(10, 0))

        bits_label = ttk.Label(size_frame, text="bits",
                               style='Info.TLabel')
        bits_label.pack(side=tk.LEFT, padx=(5, 15))

        # Выбор формата ключей
        format_label = ttk.Label(size_frame, text="Format:",
                                 style='Info.TLabel')
        format_label.pack(side=tk.LEFT)

        self.key_format_var = tk.StringVar(value="PEM")
        format_combo = ttk.Combobox(size_frame, textvariable=self.key_format_var,
                                    values=["PEM", "HEX"],
                                    state='readonly', width=6)
        format_combo.pack(side=tk.LEFT, padx=(10, 20))

        # Кнопка генерации
        gen_btn = tk.Button(size_frame, text="Generate Keys",
                            command=self.generate_keys,
                            bg=self.colors['accent'],
                            fg='white',
                            font=('Segoe UI', 10, 'bold'),
                            relief=tk.FLAT,
                            padx=20, pady=8,
                            cursor='hand2')
        gen_btn.pack(side=tk.LEFT)

        # Индикатор загрузки
        self.gen_status = ttk.Label(size_frame, text="",
                                    style='Info.TLabel')
        self.gen_status.pack(side=tk.LEFT, padx=10)

        # Публичный ключ
        pub_card = self._create_card(tab, "Public Key - X.509 (SubjectPublicKeyInfo)")
        pub_card.pack(fill=tk.BOTH, expand=True, pady=5)

        self.public_key_text = self._create_text_area(pub_card.content, height=4)
        self.public_key_text.pack(fill=tk.BOTH, expand=True, pady=5)

        pub_btn_frame = tk.Frame(pub_card.content, bg=self.colors['bg_medium'])
        pub_btn_frame.pack(fill=tk.X)

        self._create_action_btn(pub_btn_frame, "Copy",
                                lambda: self.copy_to_clipboard(self.public_key_text))
        self._create_action_btn(pub_btn_frame, "Save",
                                lambda: self.save_key(self.public_key_text, "public"))
        self._create_action_btn(pub_btn_frame, "Load",
                                lambda: self.load_key(self.public_key_text))

        # Приватный ключ
        priv_card = self._create_card(tab, "Private Key - PKCS#8")
        priv_card.pack(fill=tk.BOTH, expand=True, pady=5)

        self.private_key_text = self._create_text_area(priv_card.content, height=4)
        self.private_key_text.pack(fill=tk.BOTH, expand=True, pady=5)

        priv_btn_frame = tk.Frame(priv_card.content, bg=self.colors['bg_medium'])
        priv_btn_frame.pack(fill=tk.X)

        self._create_action_btn(priv_btn_frame, "Copy",
                                lambda: self.copy_to_clipboard(self.private_key_text))
        self._create_action_btn(priv_btn_frame, "Save",
                                lambda: self.save_key(self.private_key_text, "private"))
        self._create_action_btn(priv_btn_frame, "Load",
                                lambda: self.load_key(self.private_key_text))

    def _create_encrypt_tab(self):
        """Вкладка шифрования"""
        tab = ttk.Frame(self.notebook, style='Main.TFrame')
        self.notebook.add(tab, text="  Encrypt  ")

        # Исходное сообщение
        msg_card = self._create_card(tab, "Original Message")
        msg_card.pack(fill=tk.BOTH, expand=True, pady=(10, 5))

        self.encrypt_input = self._create_text_area(msg_card.content, height=6)
        self.encrypt_input.pack(fill=tk.BOTH, expand=True, pady=5)

        input_btn_frame = tk.Frame(msg_card.content, bg=self.colors['bg_medium'])
        input_btn_frame.pack(fill=tk.X)

        self._create_action_btn(input_btn_frame, "Paste",
                                lambda: self.paste_from_clipboard(self.encrypt_input))
        self._create_action_btn(input_btn_frame, "Clear",
                                lambda: self.clear_text(self.encrypt_input))

        # Кнопка шифрования
        btn_frame = tk.Frame(tab, bg=self.colors['bg_dark'])
        btn_frame.pack(fill=tk.X, pady=10)

        encrypt_btn = tk.Button(btn_frame, text="Encrypt",
                                command=self.encrypt,
                                bg=self.colors['success'],
                                fg='white',
                                font=('Segoe UI', 12, 'bold'),
                                relief=tk.FLAT,
                                padx=30, pady=12,
                                cursor='hand2')
        encrypt_btn.pack()

        # Зашифрованное сообщение
        result_card = self._create_card(tab, "Encrypted Message (Base64)")
        result_card.pack(fill=tk.BOTH, expand=True, pady=5)

        self.encrypt_output = self._create_text_area(result_card.content, height=6)
        self.encrypt_output.pack(fill=tk.BOTH, expand=True, pady=5)

        out_btn_frame = tk.Frame(result_card.content, bg=self.colors['bg_medium'])
        out_btn_frame.pack(fill=tk.X)

        self._create_action_btn(out_btn_frame, "Copy",
                                lambda: self.copy_to_clipboard(self.encrypt_output))

    def _create_decrypt_tab(self):
        """Вкладка дешифрования"""
        tab = ttk.Frame(self.notebook, style='Main.TFrame')
        self.notebook.add(tab, text="  Decrypt  ")

        # Зашифрованное сообщение
        cipher_card = self._create_card(tab, "Encrypted Message (Base64)")
        cipher_card.pack(fill=tk.BOTH, expand=True, pady=(10, 5))

        self.decrypt_input = self._create_text_area(cipher_card.content, height=6)
        self.decrypt_input.pack(fill=tk.BOTH, expand=True, pady=5)

        input_btn_frame = tk.Frame(cipher_card.content, bg=self.colors['bg_medium'])
        input_btn_frame.pack(fill=tk.X)

        self._create_action_btn(input_btn_frame, "Paste",
                                lambda: self.paste_from_clipboard(self.decrypt_input))
        self._create_action_btn(input_btn_frame, "Clear",
                                lambda: self.clear_text(self.decrypt_input))

        # Кнопка дешифрования
        btn_frame = tk.Frame(tab, bg=self.colors['bg_dark'])
        btn_frame.pack(fill=tk.X, pady=10)

        decrypt_btn = tk.Button(btn_frame, text="Decrypt",
                                command=self.decrypt,
                                bg=self.colors['warning'],
                                fg='white',
                                font=('Segoe UI', 12, 'bold'),
                                relief=tk.FLAT,
                                padx=30, pady=12,
                                cursor='hand2')
        decrypt_btn.pack()

        # Расшифрованное сообщение
        result_card = self._create_card(tab, "Decrypted Message")
        result_card.pack(fill=tk.BOTH, expand=True, pady=5)

        self.decrypt_output = self._create_text_area(result_card.content, height=6)
        self.decrypt_output.pack(fill=tk.BOTH, expand=True, pady=5)

        out_btn_frame = tk.Frame(result_card.content, bg=self.colors['bg_medium'])
        out_btn_frame.pack(fill=tk.X)

        self._create_action_btn(out_btn_frame, "Copy",
                                lambda: self.copy_to_clipboard(self.decrypt_output))

    def _create_status_bar(self, parent):
        """Создание статус-бара"""
        status_frame = tk.Frame(parent, bg=self.colors['bg_light'], height=30)
        status_frame.pack(fill=tk.X, pady=(20, 0))
        status_frame.pack_propagate(False)

        self.status_label = tk.Label(status_frame,
                                     text="Ready",
                                     bg=self.colors['bg_light'],
                                     fg=self.colors['text_muted'],
                                     font=('Segoe UI', 9),
                                     padx=10)
        self.status_label.pack(side=tk.LEFT, fill=tk.Y)

        version_label = tk.Label(status_frame,
                                 text="RSA v1.0",
                                 bg=self.colors['bg_light'],
                                 fg=self.colors['text_muted'],
                                 font=('Segoe UI', 9),
                                 padx=10)
        version_label.pack(side=tk.RIGHT, fill=tk.Y)

    def _create_card(self, parent, title):
        """Создание карточки с заголовком"""
        card = tk.Frame(parent, bg=self.colors['bg_medium'],
                        highlightbackground=self.colors['border'],
                        highlightthickness=1)

        header = tk.Label(card, text=title,
                          bg=self.colors['bg_medium'],
                          fg=self.colors['text'],
                          font=('Segoe UI', 11, 'bold'),
                          anchor=tk.W,
                          padx=15, pady=10)
        header.pack(fill=tk.X)

        content = tk.Frame(card, bg=self.colors['bg_medium'], padx=15, pady=5)
        content.pack(fill=tk.BOTH, expand=True)

        # Сохраняем ссылку на content в card для доступа
        card.content = content

        return card

    def _create_text_area(self, parent, height=5):
        """Создание текстового поля"""
        frame = tk.Frame(parent, bg=self.colors['bg_light'],
                         highlightbackground=self.colors['border'],
                         highlightthickness=1)

        text = tk.Text(frame, height=height,
                       bg=self.colors['bg_light'],
                       fg=self.colors['text'],
                       font=('Consolas', 10),
                       insertbackground=self.colors['accent'],
                       selectbackground=self.colors['accent'],
                       relief=tk.FLAT,
                       padx=10, pady=10,
                       wrap=tk.WORD)

        scrollbar = tk.Scrollbar(frame, command=text.yview,
                                 bg=self.colors['bg_light'],
                                 troughcolor=self.colors['bg_medium'])
        text.configure(yscrollcommand=scrollbar.set)

        scrollbar.pack(side=tk.RIGHT, fill=tk.Y)
        text.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)

        # Сохраняем ссылку на текстовый виджет в атрибуте фрейма
        frame.text_widget = text

        return frame

    def _create_action_btn(self, parent, text, command):
        """Создание кнопки действия"""
        btn = tk.Button(parent, text=text,
                        command=command,
                        bg=self.colors['bg_light'],
                        fg=self.colors['text'],
                        font=('Segoe UI', 9),
                        relief=tk.FLAT,
                        padx=12, pady=5,
                        cursor='hand2')
        btn.pack(side=tk.LEFT, padx=(0, 5))

        # Эффект наведения
        btn.bind('<Enter>', lambda e: btn.configure(bg=self.colors['border']))
        btn.bind('<Leave>', lambda e: btn.configure(bg=self.colors['bg_light']))

        return btn

    def _get_text_content(self, text_frame):
        """Получение текста из текстового поля"""
        return text_frame.text_widget.get("1.0", tk.END).strip()

    def _set_text_content(self, text_frame, content):
        """Установка текста в текстовое поле"""
        text_frame.text_widget.delete("1.0", tk.END)
        text_frame.text_widget.insert("1.0", content)

    def _set_status(self, message, status_type="info"):
        """Обновление статус-бара"""
        status_colors = {
            'info': self.colors['text_muted'],
            'success': self.colors['success'],
            'error': self.colors['error'],
            'warning': self.colors['warning']
        }
        self.status_label.configure(
            text=message,
            fg=status_colors.get(status_type, status_colors['info'])
        )

    def generate_keys(self):
        """Генерация ключей RSA"""
        self.gen_status.configure(text="Generating...")
        self._set_status("Generating keys...", "warning")

        def generate():
            try:
                bits = int(self.key_size_var.get())
                self.public_key, self.private_key = generate_keypair(bits)
                # Обновляем UI в главном потоке
                self.root.after(0, self._update_keys_display)
            except (ValueError, RuntimeError) as err:
                self.root.after(0, lambda: self._show_error(f"Generation error: {err}"))

        # Запускаем в отдельном потоке
        thread = threading.Thread(target=generate)
        thread.daemon = True
        thread.start()

    def _update_keys_display(self):
        """Обновление отображения ключей"""
        if not self.public_key or not self.private_key:
            return

        use_pem = self.key_format_var.get() == "PEM"

        if use_pem and _ensure_cryptography():
            try:
                public_pem, private_pem = keys_to_pem(self.public_key, self.private_key)
                self._set_text_content(self.public_key_text, public_pem)
                self._set_text_content(self.private_key_text, private_pem)
            except (ValueError, ImportError) as err:
                # Fallback на HEX если PEM не работает
                self._set_text_content(self.public_key_text, key_to_string(self.public_key))
                self._set_text_content(self.private_key_text, key_to_string(self.private_key))
                self._set_status(f"PEM unavailable, using HEX: {err}", "warning")
        else:
            self._set_text_content(self.public_key_text, key_to_string(self.public_key))
            self._set_text_content(self.private_key_text, key_to_string(self.private_key))

        self.gen_status.configure(text="Done!")
        format_name = "PEM" if use_pem and _ensure_cryptography() else "HEX"
        self._set_status(f"Keys generated ({self.key_size_var.get()} bit, {format_name})", "success")

    def encrypt(self):
        """Шифрование сообщения"""
        message = self._get_text_content(self.encrypt_input)

        if not message:
            self._show_error("Enter a message to encrypt")
            return

        # Получаем публичный ключ
        pub_key_str = self._get_text_content(self.public_key_text)

        if not pub_key_str:
            self._show_error("Generate or load a public key first")
            return

        try:
            # Автоопределение формата ключа
            if is_pem_format(pub_key_str):
                pub_key, _ = pem_to_keys(public_pem=pub_key_str)
            else:
                pub_key = string_to_key(pub_key_str)

            encrypted = encrypt_message(message, pub_key)
            self._set_text_content(self.encrypt_output, encrypted)
            self._set_status("Message encrypted successfully", "success")
        except (ValueError, UnicodeDecodeError) as err:
            self._show_error(f"Encryption error: {err}")

    def decrypt(self):
        """Дешифрование сообщения"""
        encrypted = self._get_text_content(self.decrypt_input)

        if not encrypted:
            self._show_error("Enter an encrypted message")
            return

        # Получаем приватный ключ
        priv_key_str = self._get_text_content(self.private_key_text)

        if not priv_key_str:
            self._show_error("Generate or load a private key first")
            return

        try:
            # Автоопределение формата ключа
            if is_pem_format(priv_key_str):
                _, priv_key = pem_to_keys(private_pem=priv_key_str)
            else:
                priv_key = string_to_key(priv_key_str)

            decrypted = decrypt_message(encrypted, priv_key)
            self._set_text_content(self.decrypt_output, decrypted)
            self._set_status("Message decrypted successfully", "success")
        except (ValueError, UnicodeDecodeError) as err:
            self._show_error(f"Decryption error: {err}")

    def copy_to_clipboard(self, text_frame):
        """Копирование в буфер обмена"""
        content = self._get_text_content(text_frame)
        if content:
            self.root.clipboard_clear()
            self.root.clipboard_append(content)
            self._set_status("Copied to clipboard", "success")
        else:
            self._set_status("Nothing to copy", "warning")

    def paste_from_clipboard(self, text_frame):
        """Вставка из буфера обмена"""
        try:
            content = self.root.clipboard_get()
            if content:
                self._set_text_content(text_frame, content)
                self._set_status("Pasted from clipboard", "success")
            else:
                self._set_status("Clipboard is empty", "warning")
        except tk.TclError:
            self._set_status("Clipboard is empty", "warning")

    def clear_text(self, text_frame):
        """Очистка текстового поля"""
        text_frame.text_widget.delete("1.0", tk.END)
        self._set_status("Field cleared", "info")

    def save_key(self, text_frame, key_type):
        """Сохранение ключа в файл"""
        content = self._get_text_content(text_frame)

        if not content:
            self._show_error(f"No {key_type} key to save")
            return

        # Определяем расширение по формату
        is_pem = is_pem_format(content)
        ext = ".pem" if is_pem else ".key"

        filename = filedialog.asksaveasfilename(
            defaultextension=ext,
            filetypes=[
                ("PEM files", "*.pem"),
                ("Key files", "*.key"),
                ("All files", "*.*")
            ],
            initialfile=f"{key_type}_key{ext}"
        )

        if filename:
            try:
                with open(filename, 'w', encoding='utf-8') as f:
                    f.write(content)
                self._set_status(f"Key saved: {filename}", "success")
            except OSError as err:
                self._show_error(f"Save error: {err}")

    def load_key(self, text_frame):
        """Загрузка ключа из файла"""
        filename = filedialog.askopenfilename(
            filetypes=[
                ("PEM files", "*.pem"),
                ("Key files", "*.key"),
                ("All files", "*.*")
            ]
        )

        if filename:
            try:
                with open(filename, 'r', encoding='utf-8') as f:
                    content = f.read().strip()

                # Проверяем валидность ключа (PEM или HEX)
                if is_pem_format(content):
                    # Проверяем PEM
                    pem_to_keys(
                        public_pem=content if 'PUBLIC' in content else None,
                        private_pem=content if 'PRIVATE' in content else None
                    )
                else:
                    string_to_key(content)

                self._set_text_content(text_frame, content)
                format_name = "PEM" if is_pem_format(content) else "HEX"
                self._set_status(f"Key loaded ({format_name}): {filename}", "success")
            except (OSError, ValueError) as err:
                self._show_error(f"Load error: {err}")

    def _show_error(self, message):
        """Отображение ошибки"""
        self._set_status(message, "error")
        messagebox.showerror("Error", message)


def main():
    """Точка входа приложения"""
    root = tk.Tk()
    RSAApp(root)
    root.mainloop()


if __name__ == "__main__":
    main()
