INSPEC_CMD=docker run -e CHEF_LICENSE=accept-silent --rm -v$(PWD):/share chef/inspec
INSPEC_TOOLS_CMD=docker run -e CHEF_LICENSE=accept-silent --rm -v$(PWD):/share mitre/inspec_tools

checklist: output.xml
.PHONY: checklist

output.xml: attributes.yml output.json
	$(INSPEC_TOOLS_CMD) inspec2xccdf -j output.json -a attributes.yml -o output.xml

output.json: inspec.yml controls/*.rb
	$(INSPEC_CMD) json . -o output.json

clean:
	rm -rf output.json output.xml
