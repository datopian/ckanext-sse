from rdflib.namespace import Namespace
from rdflib import URIRef, BNode, Literal
from rdflib.namespace import Namespace, RDF, RDFS
from ckanext.dcat.profiles import EuropeanDCATAP2Profile, URIRefOrLiteral


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

        # remove previously added triples inorder to add custom triples
        g.remove((dataset_ref, DCT.identifier, None))

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
            ('maintainer', DCT.contributor, ['maintainer_email'], Literal),
            ('date', DCT.date, None, Literal),
            ('name', DCT.identifier, None, Literal),
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

        

        
        



        

        

           
