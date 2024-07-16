import json
import rdflib
import ckan.plugins.toolkit as tk
from rdflib.namespace import Namespace
from rdflib import URIRef, BNode, Literal
from rdflib.namespace import Namespace, RDF, RDFS
from ckanext.dcat.profiles import EuropeanDCATAP2Profile, URIRefOrLiteral, CleanedURIRef
from ckanext.dcat.utils import resource_uri, dataset_uri

DCT = Namespace("http://purl.org/dc/terms/")
DCAT = Namespace("http://www.w3.org/ns/dcat#")
ib1 = Namespace("http://registry.ib1.org/ns/1.0/#")


class DCTProfile(EuropeanDCATAP2Profile):
    """
    An RDF profile for the Dublin Core Terms with custom metadata mappings.
    """

    def parse_dataset(self, dataset_dict, dataset_ref):
        # call super method
        super(DCTProfile, self).parse_dataset(dataset_dict, dataset_ref)

        resources_formats = set()
        for resource_dict in dataset_dict.get("resources", []):
            if resource_dict.get('format') and resource_dict.get('resource_type') != 'documentation':
                resources_formats.add(resource_dict.get('format'))

        dataset_dict['format'] = list(resources_formats)

        return dataset_dict

    def graph_from_dataset(self, dataset_dict, dataset_ref):
        # call super method
        super(DCTProfile, self).graph_from_dataset(dataset_dict, dataset_ref)
        g = self.g
        dataset_uri = (
            str(dataset_ref) if isinstance(dataset_ref, rdflib.term.URIRef) else ""
        )

        for format in dataset_dict.get("format", []):
            g.add((dataset_ref, DCT["format"], Literal(format)))

        # Binding the namespace
        g.bind("ib1", ib1)

        items = [
            ("source", DCT.source, None, Literal),
            ("language", DCT.language, None, URIRefOrLiteral),
            ("license_title", DCT.accessRights, None, Literal),
            ("contactPoint", DCT.contactPoint, None, Literal),
            ("conforms_to", DCT.conformsTo, None, Literal),
            ("has_version", DCT.hasVersion, None, URIRefOrLiteral),
            ("is_version_of", DCT.isVersionOf, None, URIRefOrLiteral),
            ("contact_point", DCAT.contactPoint, None, Literal),
            ("author", DCT.creator, None, Literal),
            ("contributor", DCT.contributor, None, Literal),
            ("date", DCT.date, None, Literal),
            ("relation", DCT.relation, None, Literal),
            ("date", DCT.temporal, None, Literal),
            ("ib1_trust_framework", ib1.trustFramework, None, Literal),
            ("ib1_sensitivity_class", ib1.sensitivityClass, None, Literal),
            ("ib1_dataset_assurance", ib1.datasetAssurance, None, Literal),
            ("ib1_access", ib1.access, None, Literal),
        ]

        self._add_triples_from_dict(dataset_dict, dataset_ref, items)

        g.remove((dataset_ref, DCT.identifier, None))
        g.add((dataset_ref, DCT.identifier, URIRefOrLiteral(dataset_uri)))

        # Subject
        for tag in dataset_dict.get("tags", []):
            g.add((dataset_ref, DCT.subject, Literal(tag["name"])))

        # Publisher
        if dataset_dict.get("organization"):
            publisher = dataset_dict.get("organization", {}).get("title")
            if publisher:
                g.add((dataset_ref, DCT.publisher, Literal(publisher)))

        # Type
        if dataset_dict.get("groups"):
            for group in dataset_dict.get("groups"):
                g.add((dataset_ref, DCT.type, Literal(group["title"])))

        # License
        if "license_id" not in dataset_dict:
            dataset_dict["license_id"] = self._license(dataset_ref)

        # Coverage
        if dataset_dict.get("coverage"):
            try:
                # check if coverage is a string or dict
                if isinstance(dataset_dict.get("coverage"), list):
                    coverage = json.dumps(dataset_dict.get("coverage"))
                    g.add((dataset_ref, DCT.coverage, Literal(coverage)))
            except Exception as e:
                pass

        # Resources
        for resource_dict in dataset_dict.get("resources", []):
            distribution = CleanedURIRef(resource_uri(resource_dict))

            #  Simple values
            items = [
                ("title", DCT.title, None, URIRefOrLiteral),
                ("description", DCT.description, None, URIRefOrLiteral),
            ]

            self._add_triples_from_dict(resource_dict, distribution, items)

            if dataset_dict.get("source"):
                g.add(
                    (
                        distribution,
                        DCT.source,
                        URIRefOrLiteral(dataset_dict.get("source")),
                    )
                )

            if dataset_dict.get("rights"):
                g.add(
                    (
                        distribution,
                        DCT.accessRights,
                        URIRefOrLiteral(dataset_dict.get("license_title")),
                    )
                )

            if dataset_dict.get("language"):
                g.add(
                    (
                        distribution,
                        DCT.language,
                        URIRefOrLiteral(dataset_dict.get("language")),
                    )
                )

            if resource_dict.get("size"):
                # convert bytes to megabytes
                size = int(resource_dict.get("size")) / 1000000
                g.add((distribution, DCT.SizeOrDuration, URIRefOrLiteral(size)))
