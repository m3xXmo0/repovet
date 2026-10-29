# VHS tape for the repovet demo GIF.
# Render locally with `vhs docs/demo.tape`, or through .github/workflows/demo.yml.
#
# The report is much longer than the window, so it is shown in `less`: first the header
# and the DANGER findings, a few pages of findings, then the trust and provenance
# profiles, and finally the end of the report with its closing note. The steps jump to
# landmarks instead of counting pages, so they work for any report length.

Output docs/demo.gif

Require repovet
Require less

Set Shell bash
Set Theme "Catppuccin Mocha"
Set FontSize 16
Set Width 1200
Set Height 700
Set Padding 20
Set Margin 10
Set BorderRadius 8
Set Framerate 24
Set TypingSpeed 35ms

# Keep colors although the output goes through a pipe; no search highlighting in less.
Env FORCE_COLOR "1"
Env LESS "-G"
Env LESSCHARSET "utf-8"

Hide
Type "clear"
Enter
Show
Sleep 300ms

Type "repovet scan https://github.com/m3xXmo0/repovet-demo --min-severity medium | less -R"
Sleep 600ms
Enter

# Clone and scan; less shows the report once it is complete.
Wait+Screen@60s /DANGER/

# Header, summary counts and the first findings.
Sleep 3500ms

# Two more pages of findings.
Space
Sleep 2200ms
Space
Sleep 2200ms

# Jump to the trust profile (followed by the provenance profile).
Hide
Type "/TRUST PROFILE"
Enter
Show
Sleep 3500ms

# End of the report: "Not checked" and the closing note.
Type "G"
Sleep 4500ms
