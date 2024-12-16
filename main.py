from PyQt5.QtWidgets import QMessageBox, QTextEdit, QLineEdit, QLabel, QPushButton, QVBoxLayout, QWidget
from hash import hash_message_gost
from PyQt5 import QtWidgets
import sys


class HashingApp(QWidget):
    def __init__(self):
        super().__init__()
        self.setWindowTitle("Хэширование по ГОСТ")
        self.setGeometry(100, 100, 600, 400)

        layout = QVBoxLayout()

        # Message Input
        self.message_label = QLabel("Сообщение:")
        self.message_input = QTextEdit(self)
        layout.addWidget(self.message_label)
        layout.addWidget(self.message_input)

        # Key Input
        self.key_label = QLabel("Ключ (32 байта):")
        self.key_input = QLineEdit(self)
        self.key_input.setMaxLength(32)  # Limit input to 32 characters
        layout.addWidget(self.key_label)
        layout.addWidget(self.key_input)

        # Hash Button
        self.hash_button = QPushButton("Хэшировать", self)
        self.hash_button.clicked.connect(self.hash_action)
        layout.addWidget(self.hash_button)

        # Result Output
        self.result_label = QLabel("Хэш (результат):")
        self.result_output = QTextEdit(self)
        self.result_output.setReadOnly(True)
        layout.addWidget(self.result_label)
        layout.addWidget(self.result_output)

        self.setLayout(layout)

    def hash_action(self):
        message = self.message_input.toPlainText().strip().encode()
        key = self.key_input.text().encode()

        if len(key) != 32:
            QMessageBox.critical(self, "Ошибка", "Ключ должен быть длиной 32 байта!")
            return

        try:
            result = hash_message_gost(message, key).hex()
            self.result_output.setPlainText(result)
        except Exception as e:
            QMessageBox.critical(self, "Ошибка", f"Произошла ошибка: {e}")


if __name__ == "__main__":
    app = QtWidgets.QApplication(sys.argv)
    main_window = HashingApp()
    main_window.show()
    sys.exit(app.exec_())
