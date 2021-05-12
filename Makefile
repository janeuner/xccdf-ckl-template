checklist: output.xml
.PHONY: checklist

output.xml: attributes.yml output.json
	inspec_tools inspec2xccdf -j output.json -a attributes.yml -o output.xml

output.json: inspec.yml controls/*.rb
	inspec json . > output.json

clean:
	rm -rf output.json output.xml