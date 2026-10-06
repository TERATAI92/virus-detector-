import os
import threading

from kivy.app import App
from kivy.core.window import Window
from kivy.metrics import dp
from kivy.properties import NumericProperty, ListProperty
from kivy.uix.boxlayout import BoxLayout
from kivy.uix.widget import Widget
from kivy.uix.label import Label
from kivy.uix.button import Button
from kivy.uix.textinput import TextInput
from kivy.uix.scrollview import ScrollView
from kivy.uix.filechooser import FileChooserPopup
from kivy.animation import Animation
from kivy.clock import Clock
from kivy.lang import Builder
from kivy.utils import platform

from scanner import scan_file

Window.clear_color = (0.055, 0.065, 0.095, 1)

if platform == 'android':
    try:
        from android.permissions import request_permissions, Permission
        request_permissions([
            Permission.READ_EXTERNAL_STORAGE,
            Permission.WRITE_EXTERNAL_STORAGE,
        ])
    except Exception:
        pass

KV = '''
<Card>:
    orientation: 'vertical'
    size_hint_y: None
    height: self.minimum_height
    padding: dp(14)
    spacing: dp(10)
    canvas.before:
        Color:
            rgba: 0.10, 0.12, 0.16, 1
        RoundedRectangle:
            pos: self.pos
            size: self.size
            radius: [dp(14)]

<AccentButton>:
    size_hint_y: None
    height: dp(46)
    font_size: dp(14)
    bold: True
    color: 1, 1, 1, 1
    background_normal: ''
    background_down: ''
    canvas.before:
        Color:
            rgba: self.bg_color
        RoundedRectangle:
            pos: self.pos
            size: self.size
            radius: [dp(10)]

<StyledInput>:
    size_hint_y: None
    height: dp(44)
    font_size: dp(14)
    foreground_color: 0.92, 0.95, 0.98, 1
    hint_color: 0.45, 0.52, 0.60, 1
    background_normal: ''
    background_active: ''
    padding: [dp(12), dp(10)]
    cursor_color: 0.35, 0.88, 0.72, 1
    canvas.before:
        Color:
            rgba: 0.16, 0.20, 0.26, 1
        RoundedRectangle:
            pos: self.pos
            size: self.size
            radius: [dp(10)]

<VerdictBanner>:
    size_hint_y: None
    height: dp(64)
    font_size: dp(20)
    bold: True
    color: 1, 1, 1, 1
    canvas.before:
        Color:
            rgba: self.bg
        RoundedRectangle:
            pos: self.pos
            size: self.size
            radius: [dp(14)]

<ScoreGauge>:
    size_hint_y: None
    height: dp(12)
    canvas:
        Color:
            rgba: 0.16, 0.20, 0.26, 1
        RoundedRectangle:
            pos: self.pos
            size: self.size
            radius: [dp(6)]
        Color:
            rgba: self.bar_color
        RoundedRectangle:
            pos: self.pos
            size: (self.fill_w, self.height)
            radius: [dp(6)]
'''

Builder.load_string(KV)


class Card(BoxLayout):
    pass


class AccentButton(Button):
    normal_color = ListProperty([0.16, 0.45, 0.85, 1])
    press_color = ListProperty([0.12, 0.35, 0.70, 1])
    bg_color = ListProperty([0.16, 0.45, 0.85, 1])

    def on_state(self, inst, state):
        self.bg_color = self.press_color if state == 'down' else self.normal_color

    def on_normal_color(self, inst, val):
        if self.state == 'normal':
            self.bg_color = val


class StyledInput(TextInput):
    pass


class VerdictBanner(Label):
    bg = ListProperty([0.16, 0.20, 0.26, 1])


class ScoreGauge(Widget):
    score = NumericProperty(0)
    bar_color = ListProperty([0.35, 0.88, 0.72, 1])
    fill_w = NumericProperty(0)

    def __init__(self, **kwargs):
        super().__init__(**kwargs)
        self.bind(score=self._upd, width=self._upd)

    def _upd(self, *args):
        s = min(max(self.score, 0), 100)
        self.fill_w = self.width * s / 100.0


def verdict_hex(v):
    if 'MALICIOUS' in v:
        return 'ff4d4d'
    if 'SUSPICIOUS' in v:
        return 'ffb347'
    if 'CLEAN' in v:
        return '4dd47f'
    return '9fb0c5'


class VirusDetectorUI(BoxLayout):
    def __init__(self, **kwargs):
        super().__init__(orientation='vertical', padding=dp(12), spacing=dp(10), **kwargs)

        header = Label(
            text='VIRUS DETECTOR',
            size_hint_y=None, height=dp(34),
            font_size=dp(21), bold=True,
            color=(0.35, 0.88, 0.72, 1),
        )
        subtitle = Label(
            text='hash blacklist  •  heuristik  •  YARA  •  VirusTotal',
            size_hint_y=None, height=dp(20),
            font_size=dp(11),
            color=(0.55, 0.62, 0.70, 1),
        )
        self.banner = VerdictBanner(text='SIAP MEMINDAI')
        self.gauge = ScoreGauge()

        card_path = Card()
        row_path = BoxLayout(size_hint_y=None, height=dp(44), spacing=dp(8))
        self.path = StyledInput(hint_text='Path file, contoh: /sdcard/Download/app.apk')
        row_path.add_widget(self.path)
        card_path.add_widget(row_path)

        row_btn = BoxLayout(size_hint_y=None, height=dp(46), spacing=dp(8))
        btn_pick = AccentButton(text='PILIH FILE',
                                normal_color=[0.23, 0.29, 0.40, 1],
                                press_color=[0.18, 0.23, 0.32, 1])
        btn_eicar = AccentButton(text='BUAT EICAR',
                                 normal_color=[0.50, 0.38, 0.12, 1],
                                 press_color=[0.40, 0.30, 0.09, 1])
        btn_pick.bind(on_press=self.pick_file)
        btn_eicar.bind(on_press=self.make_eicar)
        row_btn.add_widget(btn_pick)
        row_btn.add_widget(btn_eicar)
        card_path.add_widget(row_btn)

        card_scan = Card()
        self.vtkey = StyledInput(hint_text='VirusTotal API key (opsional)', password=True)
        card_scan.add_widget(self.vtkey)
        self.btn_scan = AccentButton(text='SCAN SEKARANG',
                                     normal_color=[0.13, 0.55, 0.42, 1],
                                     press_color=[0.10, 0.44, 0.34, 1])
        self.btn_scan.bind(on_press=self.start_scan)
        card_scan.add_widget(self.btn_scan)

        card_hist = Card()
        self.history = Label(
            text='Riwayat scan: belum ada',
            size_hint_y=None, halign='left', valign='top',
            font_size=dp(12), markup=True,
            color=(0.75, 0.80, 0.88, 1),
        )
        self.history.bind(texture_size=lambda i, v: setattr(i, 'height', v[1]))
        self.history.bind(width=lambda i, v: setattr(i, 'text_size', (v, None)))
        card_hist.add_widget(self.history)

        scroll = ScrollView(size_hint_y=1, do_scroll_y=True,
                            bar_color=(0.35, 0.88, 0.72, 0.6), bar_width=dp(4))
        self.report = Label(
            text='Hasil scan akan tampil di sini sebagai laporan rapi.',
            size_hint_y=None, halign='left', valign='top',
            font_size=dp(13), color=(0.85, 0.90, 0.96, 1),
            padding=[dp(4), dp(4)],
        )
        self.report.bind(texture_size=lambda i, v: setattr(i, 'height', v[1]))
        self.report.bind(width=lambda i, v: setattr(i, 'text_size', (v, None)))
        scroll.add_widget(self.report)

        self.add_widget(header)
        self.add_widget(subtitle)
        self.add_widget(self.banner)
        self.add_widget(self.gauge)
        self.add_widget(card_path)
        self.add_widget(card_scan)
        self.add_widget(card_hist)
        self.add_widget(scroll)

        self._history = []
        self._anim = None
        self._popup = None

    def pick_file(self, *args):
        start = '/sdcard' if os.path.isdir('/sdcard') else os.getcwd()
        self._popup = FileChooserPopup(path=start, size_hint=(0.95, 0.85))
        self._popup.bind(selection=self._on_pick)
        self._popup.open()

    def _on_pick(self, inst, selection):
        if selection:
            self.path.text = selection[0]
            if self._popup:
                self._popup.dismiss()

    def make_eicar(self, *args):
        eicar = 'X5O!P%@AP[4\\PZX54(P^)7CC)7}$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*'
        base = os.getcwd()
        try:
            app = App.get_running_app()
            if app and getattr(app, 'user_data_dir', None):
                base = app.user_data_dir
        except Exception:
            pass
        target = os.path.join(base, 'eicar.txt')
        try:
            with open(target, 'w', encoding='utf-8') as f:
                f.write(eicar)
            self.path.text = target
            self.report.text = 'File uji EICAR dibuat di:\n' + target + '\n\nTekan SCAN SEKARANG.'
        except Exception as e:
            self.report.text = 'Gagal membuat EICAR: ' + str(e)

    def start_scan(self, *args):
        path = self.path.text.strip()
        if not path:
            self.banner.text = 'ISI PATH DULU'
            self.banner.bg = (0.55, 0.35, 0.12, 1)
            return
        key = self.vtkey.text.strip() or None
        self.banner.text = 'MEMINDAI...'
        self.banner.bg = (0.20, 0.35, 0.55, 1)
        self.gauge.score = 0
        if self._anim is None:
            self._anim = Animation(opacity=0.45, duration=0.7) + Animation(opacity=1.0, duration=0.7)
            self._anim.repeat = True
        self._anim.start(self.banner)
        self.btn_scan.disabled = True
        threading.Thread(target=self._scan_thread, args=(path, key), daemon=True).start()

    def _scan_thread(self, path, key):
        try:
            res = scan_file(path, vt_api_key=key, rules_dir='yara_rules')
        except Exception as e:
            res = {'file': path, 'error': str(e)}
        Clock.schedule_once(lambda dt, r=res: self._finish(r), 0)

    def _finish(self, res):
        if self._anim:
            self._anim.stop(self.banner)
        self.banner.opacity = 1.0
        self.btn_scan.disabled = False

        verdict = res.get('verdict', 'UNKNOWN')
        score = res.get('score', 0)

        if 'MALICIOUS' in verdict:
            col = (0.80, 0.22, 0.22, 1)
        elif 'SUSPICIOUS' in verdict:
            col = (0.85, 0.55, 0.10, 1)
        elif 'CLEAN' in verdict:
            col = (0.15, 0.60, 0.38, 1)
        else:
            col = (0.35, 0.42, 0.52, 1)

        self.banner.text = verdict
        self.banner.bg = col
        self.gauge.score = score
        self.gauge.bar_color = col
        self.report.text = self.format_report(res)

        name = os.path.basename(res.get('file', '?'))
        self._history.insert(0, (name, verdict, score))
        self._history = self._history[:5]
        lines = []
        for nm, vd, sc in self._history:
            lines.append('[color=%s]%s[/color]  %s  (score %d)' % (verdict_hex(vd), vd, nm, sc))
        self.history.text = 'Riwayat scan:\n' + '\n'.join(lines)

    def format_report(self, res):
        L = ['FILE      : %s' % res.get('file', '-')]
        if res.get('error'):
            L.append('ERROR     : %s' % res['error'])
            return '\n'.join(L)
        h = res.get('hashes', {})
        L.append('UKURAN    : %s byte' % res.get('size', '-'))
        L.append('MD5       : %s' % h.get('md5', '-'))
        L.append('SHA1      : %s' % h.get('sha1', '-'))
        L.append('SHA256    : %s' % h.get('sha256', '-'))
        L.append('ENTROPY   : %s' % res.get('entropy', '-'))
        L.append('SCORE     : %s / 100' % res.get('score', 0))
        L.append('VERDICT   : %s' % res.get('verdict', '-'))
        L.append('')
        det = res.get('detections', [])
        if det:
            L.append('DETEKSI:')
            for d in det:
                L.append('  • ' + d)
        else:
            L.append('DETEKSI   : tidak ada temuan lokal')
        vt = res.get('virustotal')
        if vt:
            L.append('')
            if vt.get('found'):
                L.append('VIRUSTOTAL: %s malicious / %s suspicious / %s clean' % (
                    vt.get('malicious', 0), vt.get('suspicious', 0), vt.get('undetected', 0)))
            else:
                L.append('VIRUSTOTAL: %s' % vt.get('message', vt.get('error', '-')))
        m = res.get('modules', {})
        L.append('')
        L.append('MODUL: requests %s | yara %s | androguard %s' % (
            'OK' if m.get('requests') else '-',
            'OK' if m.get('yara') else '-',
            'OK' if m.get('androguard') else '-'))
        return '\n'.join(L)


class VirusDetectorApp(App):
    def build(self):
        return VirusDetectorUI()


if __name__ == '__main__':
    VirusDetectorApp().run()
