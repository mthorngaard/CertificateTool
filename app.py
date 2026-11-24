"""Certificate Tool: CSR / self-signed / local CA / PFX export / inspect, in one GUI.

Uses the same fields as IIS' "Create Certificate Request" wizard.
"""

from __future__ import annotations

import queue
import sys
import threading
import tkinter as tk
from tkinter import messagebox, ttk

import csrgen
import i18n
import settings
from i18n import _
from tab_ca import LocalCaTab
from tab_convert import ConvertTab
from tab_csr import CsrTab
from tab_export import ExportTab
from tab_inspect import InspectTab
from tab_selfsigned import SelfSignedTab
from ui_common import enable_dnd, px
from version import __version__


def enable_dpi_awareness() -> None:
    """Make text crisp on high-DPI Windows displays (must run before the first Tk window)."""
    if sys.platform != "win32":
        return
    try:
        import ctypes

        try:
            ctypes.windll.shcore.SetProcessDpiAwareness(1)
        except Exception:
            ctypes.windll.user32.SetProcessDPIAware()
    except Exception:
        pass


class App(tk.Tk):
    def __init__(self) -> None:
        super().__init__()
        self.title(f"Certificate Tool {__version__}")
        self.minsize(800, 600)
        self.busy = 0  # number of background jobs running
        self.dnd_ok = enable_dnd(self)

        style = ttk.Style(self)
        if "vista" in style.theme_names():
            style.theme_use("vista")

        self._build_menu()
        nb = ttk.Notebook(self)
        nb.pack(fill="both", expand=True, padx=8, pady=8)
        self.csr_tab = CsrTab(nb, self)
        self.ss_tab = SelfSignedTab(nb, self)
        self.ca_tab = LocalCaTab(nb, self)
        self.export_tab = ExportTab(nb, self)
        self.convert_tab = ConvertTab(nb, self)
        self.inspect_tab = InspectTab(nb, self)
        self.tabs = [
            self.csr_tab, self.ss_tab, self.ca_tab, self.export_tab, self.convert_tab, self.inspect_tab,
        ]
        for tab, title in zip(self.tabs, [
            _("Create CSR"), _("Self-signed"), _("Local CA"),
            _("Export (PFX / CRT+KEY)"), _("PFX to PEM"), _("Inspect"),
        ]):
            nb.add(tab, text=title)
        self.protocol("WM_DELETE_WINDOW", self._on_close)

        # Fit small screens: the output boxes are the flexible rows and shrink to make room
        self.update_idletasks()
        width = max(self.winfo_reqwidth(), px(self, 800))
        height = min(self.winfo_reqheight(), self.winfo_screenheight() - px(self, 100))
        self.geometry(f"{width}x{height}")

    # -------------------------------------------------------------- menu ----
    def _build_menu(self) -> None:
        bar = tk.Menu(self)
        file_menu = tk.Menu(bar, tearoff=False)
        file_menu.add_command(label=_("Clear all keys, passwords and results"), command=self.clear_all)
        file_menu.add_separator()
        file_menu.add_command(label=_("Exit"), command=self._on_close)
        bar.add_cascade(label=_("File"), menu=file_menu)

        lang_menu = tk.Menu(bar, tearoff=False)
        self.v_lang = tk.StringVar(value=settings.get_language())
        for code, label in (("auto", _("Automatic")), ("en", "English"), ("da", "Dansk")):
            lang_menu.add_radiobutton(
                label=label, value=code, variable=self.v_lang, command=self._change_language
            )
        bar.add_cascade(label=_("Language"), menu=lang_menu)

        help_menu = tk.Menu(bar, tearoff=False)
        help_menu.add_command(label=_("About"), command=self._about)
        bar.add_cascade(label=_("Help"), menu=help_menu)
        self.config(menu=bar)

    def _change_language(self) -> None:
        settings.set_language(self.v_lang.get())
        messagebox.showinfo(_("Language"), _("The language will change the next time you start the program."))

    def _about(self) -> None:
        messagebox.showinfo(
            _("About"),
            f"Certificate Tool {__version__}\n\n"
            + _("Everything runs locally. Nothing is sent over the network (except when you tick "
                "\"Download missing intermediate certificates\").")
            + "\n\nMIT License",
        )

    # --------------------------------------------------------- behaviour ----
    def run_async(self, work, on_done, disable=(), status=None) -> None:
        """Run `work()` in a thread (key generation can take seconds), then `on_done(result)`.

        `disable` buttons are disabled meanwhile; `status` is an optional (StringVar, text) pair.
        Errors are shown in a message box.
        """
        self.busy += 1
        self.config(cursor="watch")
        for w in disable:
            w.config(state="disabled")
        if status:
            status[0].set(status[1])
        results: queue.Queue = queue.Queue()

        def target() -> None:
            try:
                results.put((True, work()))
            except BaseException as exc:  # noqa: BLE001 - reported to the user
                results.put((False, exc))

        threading.Thread(target=target, daemon=True).start()

        def poll() -> None:
            try:
                ok, value = results.get_nowait()
            except queue.Empty:
                self.after(40, poll)
                return
            self.busy -= 1
            if not self.busy:
                self.config(cursor="")
            for w in disable:
                w.config(state="normal")
            if status:
                status[0].set("")
            if ok:
                on_done(value)
            else:
                text = str(value) if isinstance(value, csrgen.CsrError) else f"{type(value).__name__}: {value}"
                messagebox.showerror(_("Error"), text)

        self.after(40, poll)

    def unsaved_summary(self) -> list[str]:
        return [u for u in (t.unsaved() for t in self.tabs) if u]

    def clear_all(self) -> None:
        unsaved = self.unsaved_summary()
        if unsaved and not messagebox.askyesno(
            _("Not saved"),
            _("You have not saved {items}. They will be lost.").format(items=" / ".join(unsaved))
            + "\n\n" + _("Continue?"),
        ):
            return
        for t in self.tabs:
            t.clear()

    def _on_close(self) -> None:
        unsaved = self.unsaved_summary()
        if unsaved and not messagebox.askyesno(
            _("Not saved"),
            _("You have not saved {items}. They will be lost if you close now.").format(
                items=" / ".join(unsaved))
            + "\n\n" + _("Close anyway?"),
        ):
            return
        self.destroy()


def main() -> None:
    i18n.set_language(settings.get_language())
    enable_dpi_awareness()
    App().mainloop()


if __name__ == "__main__":
    main()
