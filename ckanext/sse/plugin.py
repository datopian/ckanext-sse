import ckan.plugins as plugins
import ckan.plugins.toolkit as toolkit
from rdflib.namespace import Namespace
from ckanext.dcat.profiles import RDFProfile
from rdflib import URIRef, BNode, Literal
from rdflib.namespace import Namespace, RDF, XSD, SKOS, RDFS

class SsePlugin(plugins.SingletonPlugin):
    plugins.implements(plugins.IConfigurer)
    
    # IConfigurer

    def update_config(self, config_):
        toolkit.add_template_directory(config_, "templates")
        toolkit.add_public_directory(config_, "public")
        toolkit.add_resource("assets", "sse")
