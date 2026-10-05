import os
import json
import threading

from kivy.app import App
from kivy.uix.boxlayout import BoxLayout
from kivy.uix.label import Label
from kivy.uix.textinput import TextInput
from kivy.uix.button import Button
from kivy.clock import Clock
from kivy.utils import platform

from scanner import scan_file

# Minta izin Android saat dijalankan sebagai APK
if platform == "android":
    try:
        from android.permissions import request_permissions, Permission
        request_permissions([
            Permission.READ_EXTERNAL_STORAGE,
            Permission.WRITE_EXTERNAL_STORAGE,
        ])
    except Exception:
        pass


class VirusDetectorUI(BoxLayout):
    def __init__(self, **kwargs):
        super().__init__(orientation="vertical", padding=12, spacing=8)

        self.add_widget(Label(
            text="Virus Detector Python",
            size_hint_y=None,
            height=36,
            bold=True
        ))

        self.path = TextInput(
            hint_text="Path file, contoh: /sdcard/Download/file.apk",
            size_hint_y=None,
            height=44
        )

        self.vtkey = TextInput(
            hint_text="VirusTotal API key (opsional)",
            password=True,
            size_hint_y=None,
            height=44
        )

        buttons = BoxLayout(size_hint_y=None, height=48, spacing=8)

        scan_btn = Button(text="Scan")
        eicar_btn = Button(text="Buat EICAR")

        scan_btn.bind(on_press=self.start_scan)
        eicar_btn.bind(on_press=self.make_eicar)

        buttons.add_widget(scan_btn)
        buttons.add_widget(eicar_btn)

        self.status = Label(
            text="Siap",
            size_hint_y=None,
            height=28
        )

        self.output = TextInput(
            readonly=True,
            text=""
        )

        self.add_widget(self.path)
        self.add_widget(self.vtkey)
        self.add_widget(buttons)
        self.add_widget(self.status)
        self.add_widget(self.output)

    def make_eicar(self, *args):
        """
        Membuat file uji EICAR.
        EICAR adalah file tes antivirus standar, tidak berbahaya.
        """
        eicar = 'X5O!P%@AP[4\\PZX54(P^)7CC)7}$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*'

        base = os.getcwd()
        try:
            app = App.get_running_app()
            if app and getattr(app, "user_data_dir", None):
                base = app.user_data_dir
        except Exception:
            pass

        path = os.path.join(base, "eicar.txt")

        try:
            with open(path, "w", encoding="utf-8") as f:
                f.write(eicar)
            self.path.text = path
            self.status.text = "File EICAR dibuat. Tekan Scan."
        except Exception as e:
            self.status.text = f"Gagal membuat EICAR: {e}"

    def start_scan(self, *args):
        path = self.path.text.strip()
        key = self.vtkey.text.strip() or None

        if not path:
            self.status.text = "Isi path file dulu"
            return

        self.status.text = "Scanning..."
        threading.Thread(
            target=self._scan_thread,
            args=(path, key),
            daemon=True
        ).start()

    def _scan_thread(self, path, key):
        try:
            result = scan_file(
                path,
                vt_api_key=key,
                rules_dir="yara_rules"
            )
            text = json.dumps(result, indent=2, ensure_ascii=False)
        except Exception as e:
            text = f"ERROR: {e}"

        Clock.schedule_once(lambda dt, t=text: self._finish(t), 0)

    def _finish(self, text):
        self.status.text = "Selesai"
        self.output.text = text


class VirusDetectorApp(App):
    def build(self):
        return VirusDetectorUI()


if __name__ == "__main__":
    VirusDetectorApp().run()
