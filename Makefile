all: lint pep8

lint:
	# Analyze code
	# don't show recommendations, info, comments, report
	# W0613 - unused argument
	# Ignore cherrypy class members as they are dynamically added
	pylint -d c,r,i,W0613 -r n -f colorized \
		   --notes= \
		   --ignored-classes=cherrypy \
		   ./ipsilon

pep8:
	# Check style consistency
	pep8 ipsilon

# Requires python-lesscpy
ui: less/ipsilon.less less/admin.less
	# Create CSS
	lesscpy less/ipsilon.less > ui/css/ipsilon.css
	lesscpy less/admin.less > ui/css/admin.css

# Requires NodeJS less and clear-css packages
# Should be removed when lesscpy starts to work properly
ui-node: less/ipsilon.less less/admin.less
	# Create and minify CSS
	lessc --clean-css less/ipsilon.less ui/css/ipsilon.css
	lessc --clean-css less/admin.less ui/css/admin.css
