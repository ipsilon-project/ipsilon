.PHONY: tests

RPMBUILD = $(PWD)/dist/rpmbuild

all: testdeps lint pep8 test
	echo "All tests passed"

testdeps:
	# Determine if test deps are installed
	# First, some binaries
	which pylint-2
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
	pylint-2 -d c,r,i,W0613 -r n -f colorized \
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
	pylint-2 -d c,r,i,W0613 -r n -f colorized \
		   --notes= \
		   --ignored-classes=cherrypy \
		   --disable=star-args \
		   ./tests
	pep8 --ignore=E121,E123,E126,E226,E24,E704,E402 tests

TESTDIR := $(shell mktemp --directory /tmp/ipsilon-testdir.XXXXXXXX)

tests:
	echo "Testdir: $(TESTDIR)"
	./runtests --path=$(TESTDIR)

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

# Running within containers
container-quickrun:
	echo "Building quickrun container ..."
	(cat tests/containers/Dockerfile-base tests/containers/Dockerfile-dev tests/containers/Dockerfile-fedora tests/containers/Dockerfile-rpm; echo "USER testuser") | sed -e 's/BASE/fedora:latest/' | docker build -f - -t ipsilon-quickrun -
	echo "quickrun container built"

quickrun: container-quickrun
	echo "Starting Quickrun ..."
	docker run -v `pwd`:/code -t --rm -it ipsilon-quickrun

# Testing within containers
container-centos6:
	@echo "Building CentOS 6 container ..."
	@(cat tests/containers/Dockerfile-base tests/containers/Dockerfile-centos tests/containers/Dockerfile-rpm; echo "USER testuser") | sed -e 's/BASE/centos:6/' | docker build -f - -q -t ipsilon-centos6 - && echo "CentOS 6 container built" || echo "CentOS 6 container build failed (optional)"

container-centos7:
	@echo "Building CentOS 7 container ..."
	@(cat tests/containers/Dockerfile-base tests/containers/Dockerfile-centos tests/containers/Dockerfile-rpm; echo "USER testuser") | sed -e 's/BASE/centos:7/' | docker build -f - -q -t ipsilon-centos7 -
	@echo "CentOS 7 container built"

container-fedora26:
	@echo "Building Fedora 26 container ..."
	@(cat tests/containers/Dockerfile-base tests/containers/Dockerfile-fedora tests/containers/Dockerfile-rpm; echo "USER testuser") | sed -e 's/BASE/fedora:26/' | docker build -f - -q -t ipsilon-fedora26 -
	@echo "Fedora 26 container built"

container-fedora27:
	@echo "Building Fedora 27 container ..."
	@(cat tests/containers/Dockerfile-base tests/containers/Dockerfile-fedora tests/containers/Dockerfile-rpm; echo "USER testuser") | sed -e 's/BASE/fedora:27/' | docker build -f - -q -t ipsilon-fedora27 -
	@echo "Fedora 27 container built"

containers: container-centos6 container-centos7 container-fedora26 container-fedora27
	@echo "Containers built"

containertest-centos6: container-centos6
	@echo "Starting CentOS 6 tests ..."
	@docker run -v `pwd`:/code -t --rm ipsilon-centos6 && echo "CentOS 6 passed" || echo "CentOS 6 failed (optional)"

containertest-centos7: container-centos7
	@echo "Starting CentOS 7 tests ..."
	@docker run -v `pwd`:/code -t --rm ipsilon-centos7
	@echo "CentOS 7 passed"

containertest-fedora26: container-fedora26
	@echo "Starting Fedora 26 tests ..."
	@docker run -v `pwd`:/code -t --rm ipsilon-fedora26
	@echo "Fedora 26 passed"

containertest-fedora27: container-fedora27
	@echo "Starting Fedora 27 tests ..."
	@docker run -v `pwd`:/code -t --rm ipsilon-fedora27
	@echo "Fedora 27 passed"

containertest-lint: container-centos7
	@echo "Starting code lint tests ..."
	@docker run -v `pwd`:/code -t --rm --entrypoint /usr/bin/make ipsilon-centos7 lint pep8
	@echo "Code lint tests passed"

containertest: containertest-lint containertest-centos6 containertest-centos7 containertest-fedora26 containertest-fedora27
	@echo "Container tests passed"
