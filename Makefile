RPMBUILD = $(PWD)/dist/rpmbuild

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

clean:
	rm -fr testdir

lp-test:
	pylint -d c,r,i,W0613 -r n -f colorized \
		   --notes= \
		   --ignored-classes=cherrypy \
		   ./tests
	pep8 tests

test: lp-test
	PYTHONPATH=./ ./ipsilon/tools/saml2metadata.py

sdist:
	python setup.py sdist

rpmroot:
	rm -rf $(RPMBUILD)
	mkdir -p $(RPMBUILD)/BUILD
	mkdir -p $(RPMBUILD)/RPMS
	mkdir -p $(RPMBUILD)/SOURCES
	mkdir -p $(RPMBUILD)/SPECS
	mkdir -p $(RPMBUILD)/SRPMS

rpmdistdir:
	mkdir -p dist/rpms
	mkdir -p dist/srpms

rpms: rpmroot rpmdistdir sdist
	cp dist/ipsilon*.tar.gz $(RPMBUILD)/SOURCES/
	rpmbuild --define "_topdir $(RPMBUILD)" -ba contrib/fedora/ipsilon.spec
	mv $(RPMBUILD)/RPMS/*/ipsilon-*.rpm dist/rpms/
	mv $(RPMBUILD)/SRPMS/ipsilon-*.src.rpm dist/srpms/
	rm -rf $(RPMBUILD)

rpms: sdist
