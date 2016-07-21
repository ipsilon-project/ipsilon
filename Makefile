RPMBUILD = $(PWD)/dist/rpmbuild

all: testdeps lint pep8 test
	echo "All tests passed"

testdeps:
	# Determine if test deps are installed
	# First, some binaries
	which pylint
	which pep8
	which httpd
	which postgres
	which openssl
	which slapd
	# Now, python libraries
	python -c 'import argparse'
	python -c 'import requests_kerberos'
	python -c 'import openid'
	python -c 'import openid_teams'
	python -c 'import openid_cla'
	python -c 'import cherrypy'
	python -c 'import M2Crypto'
	python -c 'import lasso'
	python -c '__requires__ = ["sqlalchemy >= 0.8"]; import pkg_resources; import sqlalchemy'
	python -c 'import ldap'
	python -c 'import pam'
	python -c 'import fedora'
	python -c 'import ipapython'
	python -c 'import jinja2'
	python -c 'import psycopg2'
	# And now everything else
	ls /usr/lib*/security/pam_sss.so
	ls /usr/lib*/libsss_simpleifp.so.0
	ls /usr/lib*/httpd/modules/mod_wsgi.so
	ls /usr/libexec/mod_auth_mellon

lint:
	# Analyze code
	# don't show recommendations, info, comments, report
	# W0613 - unused argument
	# Ignore cherrypy class members as they are dynamically added
	# Ignore IPA API class members as they are dynamically added
	pylint -d c,r,i,W0613 -r n -f colorized \
		   --notes= \
		   --ignored-classes=cherrypy,API \
		   --disable=star-args \
		   ./ipsilon

pep8:
	# Check style consistency
	pep8 ipsilon

# Requires NodeJS less and clear-css packages
ui-node: less/ipsilon.less less/admin.less

	# Create and minify CSS
	#lessc --clean-css less/ipsilon.less ui/css/ipsilon.css
	#lessc --clean-css less/admin.less ui/css/admin.css

	# FIXME: temporarily disable clean-css for development
	lessc less/ipsilon.less ui/css/ipsilon.css
	lessc less/admin.less ui/css/admin.css
	lessc less/styles.less ui/css/styles.css
	lessc less/patternfly/patternfly.less ui/css/patternfly.css

clean:
	rm -fr testdir cscope.out
	find ./ -name '*.pyc' -exec rm -f {} \;

cscope:
	git ls-files | xargs pycscope

lp-test:
	pylint -d c,r,i,W0613 -r n -f colorized \
		   --notes= \
		   --ignored-classes=cherrypy \
		   --disable=star-args \
		   ./tests
	pep8 --ignore=E121,E123,E126,E226,E24,E704,E402 tests

wrappers:
	#rm -fr wrapdir
	#mkdir wrapdir
	#LD_PRELOAD=libsocket_wrapper.so
	#SOCKET_WRAPPER_DIR=wrapdir
	#SOCKET_WRAPPER_DEFAULT_IFACE=9

TESTDIR := $(shell mktemp --directory /tmp/ipsilon-testdir.XXXXXXXX)

tests: wrappers
	echo "Testdir: $(TESTDIR)"
	PYTHONPATH=./ ./tests/tests.py --path=$(TESTDIR) --test=test1
	PYTHONPATH=./ ./tests/tests.py --path=$(TESTDIR) --test=testlogout
	PYTHONPATH=./ ./tests/tests.py --path=$(TESTDIR) --test=testnameid
	PYTHONPATH=./ ./tests/tests.py --path=$(TESTDIR) --test=testrest
	PYTHONPATH=./ ./tests/tests.py --path=$(TESTDIR) --test=testmapping
	PYTHONPATH=./ ./tests/tests.py --path=$(TESTDIR) --test=testgssapi
	PYTHONPATH=./ ./tests/tests.py --path=$(TESTDIR) --test=attrs
	PYTHONPATH=./ ./tests/tests.py --path=$(TESTDIR) --test=trans
	PYTHONPATH=./ ./tests/tests.py --path=$(TESTDIR) --test=pgdb
	PYTHONPATH=./ ./tests/tests.py --path=$(TESTDIR) --test=fconf
	PYTHONPATH=./ ./tests/tests.py --path=$(TESTDIR) --test=ldap
	PYTHONPATH=./ ./tests/tests.py --path=$(TESTDIR) --test=ldapdown
	PYTHONPATH=./ ./tests/tests.py --path=$(TESTDIR) --test=openid
	PYTHONPATH=./ ./tests/tests.py --path=$(TESTDIR) --test=openidc
	PYTHONPATH=./ ./tests/tests.py --path=$(TESTDIR) --test=dbupgrades

test: lp-test unittests tests

unittests:
	PYTHONPATH=./ ./ipsilon/tools/saml2metadata.py
	PYTHONPATH=./ python ./ipsilon/util/policy.py

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
	rpmbuild --define "gittag .git`git rev-parse --short HEAD`" --define "builddate .`date +%Y%m%d%H%M`" --define "_topdir $(RPMBUILD)" -ba contrib/fedora/ipsilon.spec
	mv $(RPMBUILD)/RPMS/*/ipsilon-*.rpm dist/rpms/
	mv $(RPMBUILD)/SRPMS/ipsilon-*.src.rpm dist/srpms/
	rm -rf $(RPMBUILD)

releaserpms: rpmroot rpmdistdir sdist
	cp dist/ipsilon*.tar.gz $(RPMBUILD)/SOURCES/
	rpmbuild --define "_topdir $(RPMBUILD)" -ba contrib/fedora/ipsilon.spec
	mv $(RPMBUILD)/RPMS/*/ipsilon-*.rpm dist/rpms/
	mv $(RPMBUILD)/SRPMS/ipsilon-*.src.rpm dist/srpms/
	rm -rf $(RPMBUILD)
