
all: prepare tests clean

prepare:
	mkdir -p config workspace
	cp ../config/*.yml config/
	sed -i \
		-e 's,/etc/pki,./workspace,g' \
		-e 's,as65342.net,example.com,g' \
		-e 's,as65342,test,g' \
		-e 's,AS65342,Test,g' \
		-e 's,NL,Country,g' \
		-e 's,Utrecht,Province,g' \
		-e 's,Amersfoort,City,g' \
		-e 's,PKI services,Organizational Unit,g' \
		./config/pki.yml
	cp -Rp ../templates workspace/

tests: prepare
	NOSE_COVER_PACKAGE='pkilib' nosetests -v \
		--with-coverage \
		--cover-xml \
		--with-xunit \
		pkilib/utils/*.py \
		pkilib/log/*.py \
		pkilib/ssl/*.py \
		pkilib/ca/*.py \
		|| true

clean:
	rm -rf config workspace pki.log passwd.input *.xml
