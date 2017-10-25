'''
Faraday Penetration Test IDE
Copyright (C) 2013  Infobyte LLC (http://www.infobytesec.com/)
'''
import sys, os, string, ast, json

try:
    import xml.etree.cElementTree as ET
    from xml.etree.cElementTree import Element, ElementTree
except ImportError:
    import xml.etree.ElementTree as ET
    from xml.etree.ElementTree import Element, ElementTree

the_config = None

CONST_APPNAME = "appname"
CONST_CONFIG_PATH = "config_path"
CONST_DATA_PATH = "data_path"
CONST_DEBUG_STATUS = "debug_status"
CONST_HOME_PATH = "home_path"
CONST_PERSISTENCE_PATH = "persistence_path"
CONST_VERSION = "version"
CONST_PLUGIN_SETTINGS = "plugin_settings"


DEFAULT_XML = os.path.dirname(__file__) +  "/default.xml"


class Configuration:

    def __init__(self, xml_file=DEFAULT_XML):
        """ Initializer that handles a configuration automagically. """

        self.filepath = xml_file
    
    def init(self):
        """ Must be called after the constructor and before some obj tries to read some conf """
        if self._isConfig(): self._getConfig()

    def _isConfig(self):
        """ Checks whether the given file exists and belongs
        to faraday's configuration syntax"""

        root = f = None
        try:
            f = open(self.filepath, 'rb')
            try:
                for event, elem in ET.iterparse(f, ('start', )):
                    root = elem.tag
                    break
            except SyntaxError, err:
                print "Not an xml file.\n %s" % (err)
                return False

        except IOError, err:
            print "Error while opening file.\n%s. %s" % (err, self.filepath)
            return False

        finally:
            if f: f.close()
        return (root == "unisecbarber")

    def _getTree(self):
        """ Returns an XML tree read from file. """

        f = open(self.filepath)
        try:
            tree = ET.fromstring(f.read())
        except SyntaxError, err:
            print "SyntaxError: %s. %s" % (err, self.filepath)
            return None
        return tree

    def _getValue(self, tree, var, default = None):
        """ Returns generic value from a variable on an XML tree. """

        elem = tree.findall(var)
        if not(elem):
            return default

        return elem[0].text

    def _getConfig(self):
        """ Gathers all configuration data from self.filepath, and
            completes private attributes with such information. """

        tree = self._getTree()
        if tree:
            self._appname = self._getValue(tree, CONST_APPNAME)
            self._config_path = self._getValue(tree, CONST_CONFIG_PATH)
            self._data_path = self._getValue(tree, CONST_DATA_PATH)
            self._debug_status = self._getValue(tree, CONST_DEBUG_STATUS)
            self._version = self._getValue(tree, CONST_VERSION)
            self._plugin_settings = json.loads(self._getValue(tree, CONST_PLUGIN_SETTINGS, default = "{}"))
            self._persistence_path = self._getValue(tree, CONST_PERSISTENCE_PATH)
            self._home_path = self._getValue(tree, CONST_HOME_PATH)

    def getAppname(self):
        return self._appname

    def getApiConInfoPort(self):
        return "NOT_IMPLEMENTED"

    def getApiConInfoHost(self):
        return "NOT_IMPLEMENTED"

    def getHomePath(self):
        return os.path.expanduser(self._home_path)

    def getConfigPath(self):
        return os.path.expanduser(self._config_path)

    def getDataPath(self):
        return os.path.expanduser(self._data_path)

    def getDebugStatus(self):
        return int(self._debug_status)

    def getPersistencePath(self):
        return os.path.expanduser(self._persistence_path)

    def getVersion(self):
        return self._version

    def getPluginSettings(self):
        return self._plugin_settings

    def setAppname(self, val):
        self._appname = val

    def setConfigPath(self, val):
        self._config_path = val

    def setDataPath(self, val):
        self._data_path = val

    def setDebugStatus(self, val):
        self._debug_status = int(val)

    def setHomePath(self, val):
        self._home_path = val

    def setVersion(self, val):
        self._version = val

    def setPluginSettings(self, settings):
        self._plugin_settings = settings

    def indent(self, elem, level=0):
        """ Indents the tree to make a pretty view of it. """

        i = "\n" + level*"  "
        if len(elem):
            if not elem.text or not elem.text.strip():
                elem.text = i + "  "
            if not elem.tail or not elem.tail.strip():
                elem.tail = i
            for elem in elem:
                self.indent(elem, level+1)
            if not elem.tail or not elem.tail.strip():
                elem.tail = i
        else:
            if level and (not elem.tail or not elem.tail.strip()):
                elem.tail = i


    def saveConfig(self, xml_file="~/.unisecbarber/config/user.xml"):
        """ Saves XML config on new file. """

        ROOT = Element("unisecbarber")

        tree = self._getTree()

        APPNAME = Element(CONST_APPNAME)
        APPNAME.text = self.getAppname()
        ROOT.append(APPNAME)
    
        CONFIG_PATH = Element(CONST_CONFIG_PATH)
        CONFIG_PATH.text = self.getConfigPath()
        ROOT.append(CONFIG_PATH)

        DATA_PATH = Element(CONST_DATA_PATH)
        DATA_PATH.text = self.getDataPath()
        ROOT.append(DATA_PATH)

        DEBUG_STATUS = Element(CONST_DEBUG_STATUS)
        DEBUG_STATUS.text = str(self.getDebugStatus())
        ROOT.append(DEBUG_STATUS)

        HOME_PATH = Element(CONST_HOME_PATH)
        HOME_PATH.text = self.getHomePath()
        ROOT.append(HOME_PATH)

        PERSISTENCE_PATH = Element(CONST_PERSISTENCE_PATH)
        PERSISTENCE_PATH.text = self.getPersistencePath()
        ROOT.append(PERSISTENCE_PATH)

        VERSION = Element(CONST_VERSION)
        VERSION.text = self.getVersion()
        ROOT.append(VERSION)

        PLUGIN_SETTINGS = Element(CONST_PLUGIN_SETTINGS)
        PLUGIN_SETTINGS.text = json.dumps(self.getPluginSettings())
        ROOT.append(PLUGIN_SETTINGS)

        self.indent(ROOT, 0)
        xml_file = os.path.expanduser(xml_file)
        ElementTree(ROOT).write(xml_file)

def getInstanceConfiguration():
    global the_config
    if the_config is None:
        if os.path.exists(os.path.expanduser("~/.unisecbarber/config/user.xml")):
            the_config = Configuration(os.path.expanduser("~/.unisecbarber/config/user.xml"))
        else:
            the_config = Configuration(os.path.expanduser("~/.unisecbarber/config/config.xml"))
    return the_config
