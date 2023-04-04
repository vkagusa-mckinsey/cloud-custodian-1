SELF_MAKE := $(lastword $(MAKEFILE_LIST))
PKG_REPO = testpypi
PKG_SET := tools/c7n_gcp tools/c7n_kube tools/c7n_openstack tools/c7n_mailer tools/c7n_logexporter tools/c7n_policystream tools/c7n_trailcreator tools/c7n_org tools/c7n_sphinxext tools/c7n_terraform tools/c7n_awscc tools/c7n_tencentcloud tools/c7n_azure

PLATFORM_ARCH := $(shell python3 -c "import platform; print(platform.machine())")
PLATFORM_OS := $(shell python3 -c "import platform; print(platform.system())")
PY_VERSION := $(shell python3 -c "import sys; print('%s.%s' % (sys.version_info.major, sys.version_info.minor))")


ifneq "$(findstring $(PLATFORM_OS), Linux Darwin)" ""
  ifneq "$(findstring $(PY_VERSION), 3.10)" ""
    PKG_SET := tools/c7n_left $(PKG_SET)
  endif
endif


install:
	python3 -m venv .
	. bin/activate && pip install -r requirements-dev.txt

install-poetry:
	poetry install
	for pkg in $(PKG_SET); do echo "Install $$pkg" && cd $$pkg && poetry install --all-extras && cd ../..; done

pkg-rebase:
	rm -f poetry.lock
	for pkg in $(PKG_SET); do cd $$pkg && echo $$pkg && rm -f poetry.lock && cd ../..; done

	rm -f setup.py
	for pkg in $(PKG_SET); do cd $$pkg && echo $$pkg && rm -f setup.py && cd ../..; done

	rm -f requirements.txt
	for pkg in $(PKG_SET); do cd $$pkg && echo $$pkg && rm -f requirements.txt && cd ../..; done

	@$(MAKE) -f $(SELF_MAKE) pkg-update
	git add poetry.lock
	for pkg in $(PKG_SET); do cd $$pkg && echo $$pkg && git add poetry.lock && cd ../..; done

	@$(MAKE) -f $(SELF_MAKE) pkg-gen-setup
	git add setup.py
	for pkg in $(PKG_SET); do cd $$pkg && echo $$pkg && git add setup.py && cd ../..; done

	@$(MAKE) -f $(SELF_MAKE) pkg-gen-requirements
	git add requirements.txt
	for pkg in $(PKG_SET); do cd $$pkg && echo $$pkg && git add requirements.txt && cd ../..; done

pkg-update:
	poetry update
	for pkg in $(PKG_SET); do cd $$pkg && echo $$pkg && poetry update && cd ../..; done

pkg-show-update:
	poetry show -o
	for pkg in $(PKG_SET); do cd $$pkg && echo $$pkg && poetry show -o && cd ../..; done

pkg-freeze-setup:
	python3 tools/dev/poetrypkg.py gen-frozensetup -p .
	for pkg in $(PKG_SET); do python3 tools/dev/poetrypkg.py gen-frozensetup -p $$pkg; done

pkg-gen-setup:
	python3 tools/dev/poetrypkg.py gen-setup -p .
	for pkg in $(PKG_SET); do python3 tools/dev/poetrypkg.py gen-setup -p $$pkg; done

pkg-gen-requirements:
# we have todo without hashes due to https://github.com/pypa/pip/issues/4995
	poetry export --dev --without-hashes -f requirements.txt > requirements.txt
	for pkg in $(PKG_SET); do cd $$pkg && poetry export --without-hashes -f requirements.txt > requirements.txt && cd ../..; done

pkg-increment:
# increment versions
	poetry version patch
	for pkg in $(PKG_SET); do cd $$pkg && poetry version patch && cd ../..; done
# generate setup
	@$(MAKE) pkg-gen-setup
	python3 tools/dev/poetrypkg.py gen-version-file -p . -f c7n/version.py

pkg-build-wheel:
# azure pin uses ancient wheel version, upgrade first
	pip install -U wheel
# clean up any artifacts first
	rm -f dist/*
	for pkg in $(PKG_SET); do cd $$pkg && rm -f dist/* && cd ../..; done
# generate sdist
	python setup.py bdist_wheel
	for pkg in $(PKG_SET); do cd $$pkg && python setup.py bdist_wheel && cd ../..; done
# check wheel
	twine check dist/*
	for pkg in $(PKG_SET); do cd $$pkg && twine check dist/* && cd ../..; done

pkg-publish-wheel:
# upload to test pypi
	twine upload -r $(PKG_REPO) dist/*
	for pkg in $(PKG_SET); do cd $$pkg && twine upload -r $(PKG_REPO) dist/* && cd ../..; done

test-poetry:
	. $(PWD)/test.env && poetry run pytest -n auto tests tools

test-poetry-cov:
	. $(PWD)/test.env && poetry run pytest -n auto \
            --cov c7n --cov tools/c7n_azure/c7n_azure \
            --cov tools/c7n_gcp/c7n_gcp --cov tools/c7n_kube/c7n_kube \
            --cov tools/c7n_mailer/c7n_mailer \
            tests tools {posargs}

test:
	./bin/tox -e py38

ftest:
	C7N_FUNCTIONAL=yes AWS_DEFAULT_REGION=us-east-2 pytest tests -m functional

ttest:
	C7N_FUNCTIONAL=yes AWS_DEFAULT_REGION=us-east-2 pytest tests -m terraform

sphinx:
# if this errors either tox -e docs or cd tools/c7n_sphinext && poetry install
	make -f docs/Makefile.sphinx html

ghpages:
	-git checkout gh-pages && \
	mv docs/build/html new-docs && \
	rm -rf docs && \
	mv new-docs docs && \
	git add -u && \
	git add -A && \
	git commit -m "Updated generated Sphinx documentation"

lint:
	flake8 c7n tests tools

clean:
	make -f docs/Makefile.sphinx clean
	rm -rf .tox .Python bin include lib pip-selfcheck.json

analyzer-bandit:
	bandit -i -s B101,B311 \
	-r tools/c7n_azure/c7n_azure \
	 tools/c7n_gcp/c7n_gcp \
	 tools/c7n_terraform/c7n_terraform \
	 tools/c7n_guardian/c7n_guardian \
	 tools/c7n_org/c7n_org \
	 tools/c7n_mailer/c7n_mailer \
	 tools/c7n_policystream/policystream.py \
	 tools/c7n_trailcreator/c7n_trailcreator \
	 c7n


analyzer-semgrep:
	semgrep --error --verbose --config p/security-audit \
	 tools/c7n_azure/c7n_azure \
	 tools/c7n_gcp/c7n_gcp \
	 tools/c7n_terraform/c7n_terraform \
	 tools/c7n_guardian/c7n_guardian \
	 tools/c7n_org/c7n_org \
	 tools/c7n_mailer/c7n_mailer \
	 tools/c7n_policystream/policystream.py \
	 tools/c7n_trailcreator/c7n_trailcreator \
	 c7n
