import urllib.parse
import json
import ckan.plugins.toolkit as tk
from rdflib.namespace import Namespace
from rdflib import URIRef, BNode, Literal
from rdflib.namespace import Namespace, RDF, RDFS
from ckanext.dcat.profiles import EuropeanDCATAP2Profile, URIRefOrLiteral, CleanedURIRef
from ckanext.dcat.utils import resource_uri, dataset_uri

DCT = Namespace("http://purl.org/dc/terms/")
DCAT = Namespace("http://www.w3.org/ns/dcat#")

class DCTProfile(EuropeanDCATAP2Profile):
    '''
    An RDF profile for the Dublin Core Terms with custom metadata mappings.
    '''
            
    def parse_dataset(self, dataset_dict, dataset_ref):
         # call super method 
        super(DCTProfile, self).parse_dataset(dataset_dict, dataset_ref)

        return dataset_dict

    def graph_from_dataset(self, dataset_dict, dataset_ref):
        # call super method
        super(DCTProfile, self).graph_from_dataset(dataset_dict, dataset_ref)
        g = self.g

        items = [
            ('source', DCT.source, None, Literal),
            ('language', DCT.title, None, Literal),
            ('rights', DCT.accessRights, None, Literal),
            ('contactPoint', DCT.contactPoint, None, Literal),
            ('conforms_to', DCT.conformsTo, None, Literal),
            ('has_version', DCT.hasVersion, None, URIRefOrLiteral),
            ('is_version_of', DCT.isVersionOf, None, URIRefOrLiteral),
            ('contact_point', DCAT.contactPoint, None, Literal),
            ('author', DCT.creator, None, Literal),
            ('contributor', DCT.contributor, None, Literal),
            ('metadata_modified', DCT.date, None, Literal),
            ('identifier', DCT.identifier, 'name', Literal),
            ('date', DCT.temporal, None, Literal),
        ]
        self._add_triples_from_dict(dataset_dict, dataset_ref, items)


        # Subject 
        for tag in dataset_dict.get('tags', []):
            g.add((dataset_ref, DCT.subject, Literal(tag['name'])))

        # Publisher
        if dataset_dict.get('organization'):
            publisher = dataset_dict.get('organization', {}).get('title')
            if publisher:
                g.add((dataset_ref, DCT.publisher, Literal(publisher)))

        # Type 
        if dataset_dict.get('groups'):
            for group in dataset_dict.get('groups'):
                g.add((dataset_ref, DCT.type, Literal(group['title'])))
        
        # License
        if 'license_id' not in dataset_dict:
            dataset_dict['license_id'] = self._license(dataset_ref)

        # Coverage
        if dataset_dict.get('coverage'):
            try:
                # check if coverage is a string or dict
                if isinstance(dataset_dict.get('coverage'), str):
                    coverages_dict = json.loads(dataset_dict.get('coverage'))
                else:
                    coverages_dict = dataset_dict.get('coverage')
                    
                if 'temporal' in coverages_dict.get('type'):
                    g.add((dataset_ref, DCT.coverage, 
                        Literal('%s - %s' % (coverages_dict.get('start'), 
                                                coverages_dict.get('end')))))
                    
                elif 'spatial' in coverages_dict.get('type'):
                    g.add((dataset_ref, DCT.coverage, 
                        Literal('%s , %s' % (coverages_dict.get('location_name'), 
                                                coverages_dict.get('location_geojson')))))
            except:
                pass
          
        if dataset_dict.get('relationships_as_object'):
            for rel in dataset_dict.get('relationships_as_object'):
                # if dict has __extras key
                if '__extras' in rel:
                    obj_rel = rel['__extras']['subject_package_id']
                else:
                    obj_rel = rel['subject_package_id']

                dataset_dict = tk.get_action('package_show')(data_dict={'id': obj_rel})
                rel_dataset_url = dataset_uri(dataset_dict)
                g.add((dataset_ref, DCT.relation, URIRefOrLiteral(rel_dataset_url)))


        if dataset_dict.get('relationships_as_subject'):
            for rel in dataset_dict.get('relationships_as_subject'):
                # if dict has __extras key
                if '__extras' in rel:
                    obj_rel = rel['__extras']['object_package_id']
                else:
                    obj_rel = rel['object_package_id']

                dataset_dict = tk.get_action('package_show')(data_dict={'id': obj_rel})
                rel_dataset_url = dataset_uri(dataset_dict)
                g.add((dataset_ref, DCT.relation, URIRefOrLiteral(rel_dataset_url)))


        # Resources
        for resource_dict in dataset_dict.get('resources', []):

            distribution = CleanedURIRef(resource_uri(resource_dict))
            
            #  Simple values
            items = [
                ('title', DCT.title, None, URIRefOrLiteral),
                ('description', DCT.description, None, URIRefOrLiteral),
            ]
            
            self._add_triples_from_dict(resource_dict, distribution, items)

            if dataset_dict.get('source'):
                g.add((distribution, DCT.source, URIRefOrLiteral(dataset_dict.get('source'))))

            if dataset_dict.get('rights'):
                g.add((distribution, DCT.accessRights, URIRefOrLiteral(dataset_dict.get('rights'))))
            
            if dataset_dict.get('language'):
                g.add((distribution, DCT.language, URIRefOrLiteral(dataset_dict.get('language'))))

            if resource_dict.get('size'):
                # convert bytes to megabytes
                size = int(resource_dict.get('size')) / 1000000
                g.add((distribution, DCT.SizeOrDuration, URIRefOrLiteral(size)))
