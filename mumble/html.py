from xml.sax.saxutils import escape as esc, unescape as unesc
# escape() and unescape() takes care of &, < and >.
html_escape_table = {
	'"': "&quot;",
	"'": "&apos;"
}
html_unescape_table = {v: k for k, v in html_escape_table.items()}


def escape(text):
	return esc(text, html_escape_table)


def unescape(text):
	return unesc(text, html_unescape_table)
