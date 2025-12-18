package handlersv3

import (
	"fmt"

	"github.com/AustralianCyberSecurityCentre/azul-bedrock/v10/gosrc/events"
	bh "github.com/AustralianCyberSecurityCentre/azul-plugin-virustotal.git/virustotal/vtmap/basehandlerv3"
	"github.com/tidwall/gjson"
)

var vtToAzFeatDotNetAssembly = []bh.VtPathToAzFeature{
	bh.NewVtPathToAzFeat("assembly_data", bh.VtTypeDict, "assembly_version", bh.AzFTString, "dotNetAssembly - basic data about the assembly manifest.", bh.AddSpecialFeatureHandlerFn(mergeVersionInfoHandler)),
	//bh.NewVtPathToAzFeat("assembly_data.buildnumber", bh.VtTypeInteger, "assembly_data_buildnumber", bh.AzFTInteger, "dotNetAssembly - build number."), // merged - major.minor.build.revison - https://learn.microsoft.com/en-us/dotnet/standard/assembly/versioning
	bh.NewVtPathToAzFeat("assembly_data.culture", bh.VtTypeString, "assembly_culture", bh.AzFTString, "dotNetAssembly - culture-specific information."),
	// bh.NewVtPathToAzFeat("assembly_data.flags", bh.VtTypeInteger, "assembly_data_flags", bh.AzFTInteger, "dotNetAssembly - specific characteristics of the assembly (i.e. x86, AMD64, etc.)"),
	bh.NewVtPathToAzFeat("assembly_data.flags_text", bh.VtTypeString, "assembly_flags_text", bh.AzFTString, "dotNetAssembly - human-readable version of flags."),
	bh.NewVtPathToAzFeat("assembly_data.hashalgid", bh.VtTypeInteger, "assembly_hashalgid", bh.AzFTInteger, "dotNetAssembly - id of hash used when signed."),
	// bh.NewVtPathToAzFeat("assembly_data.majorversion", bh.VtTypeInteger, "assembly_version_major", bh.AzFTInteger, "dotNetAssembly - major version."), // merged
	// bh.NewVtPathToAzFeat("assembly_data.minorversion", bh.VtTypeInteger, "assembly_version_minor", bh.AzFTInteger, "dotNetAssembly - minor version."), // merged
	bh.NewVtPathToAzFeat("assembly_data.name", bh.VtTypeString, "assembly_name", bh.AzFTString, "dotNetAssembly - assembly name."),
	bh.NewVtPathToAzFeat("assembly_data.pubkey", bh.VtTypeString, "assembly_pubkey", bh.AzFTString, "dotNetAssembly - public key."),
	//bh.NewVtPathToAzFeat("assembly_data.revisionnumber", bh.VtTypeInteger, "assembly_revisionnumber", bh.AzFTInteger, "dotNetAssembly - revision number."), // merged
	// bh.NewVtPathToAzFeat("assembly_flags", bh.VtTypeInteger, "assembly_flags", bh.AzFTInteger, "dotNetAssembly - other flags regarding the assembly (i.e. requiring 32 bits, etc.)"),
	bh.NewVtPathToAzFeat("assembly_flags_txt", bh.VtTypeString, "assembly_flags_txt", bh.AzFTString, "dotNetAssembly - human-readable version of assembly_flags."),
	bh.NewVtPathToAzFeat("assembly_name", bh.VtTypeString, "assembly_name", bh.AzFTString, "dotNetAssembly - assembly name."),
	bh.NewVtPathToAzFeat("clr_meta_version", bh.VtTypeString, "clr_meta_version", bh.AzFTString, "dotNetAssembly - version number of Common Language Runtime metadata."),
	bh.NewVtPathToAzFeat("clr_version", bh.VtTypeString, "clr_version", bh.AzFTString, "dotNetAssembly - Common Language Runtime version."),
	bh.NewVtPathToAzFeat("entry_point_rva", bh.VtTypeInteger, "entry_point_rva", bh.AzFTInteger, "dotNetAssembly - entry point Relative Virtual Address."),
	bh.NewVtPathToAzFeat("entry_point_token", bh.VtTypeInteger, "entry_point_token", bh.AzFTInteger, "dotNetAssembly - entry point of the program."),
	bh.NewVtPathToAzFeat("external_assemblies", bh.VtTypeDict, "external_assemblies", bh.AzFTString, "dotNetAssembly - other assemblies used by this one, with name and version. Key is the assembly name and it has a dictionary as value with a version key.", bh.AddSpecialFeatureHandlerFn(externalAssembliesHandler)),
	// bh.NewVtPathToAzFeat("exported_types", bh.VtTypeListOfDict, "exported_types", bh.dont-map, "dotNetAssembly - contains exported types, with name and name spaces:"),
	bh.NewVtPathToAzFeat("exported_types.name", bh.VtTypeString, "exported_types_name", bh.AzFTString, "dotNetAssembly - type name.", bh.AddListOfDictHandling("exported_types", "name")),
	bh.NewVtPathToAzFeat("exported_types.namespace", bh.VtTypeString, "exported_types_namespace", bh.AzFTString, "dotNetAssembly - type namespace.", bh.AddListOfDictHandling("exported_types", "name")),
	bh.NewVtPathToAzFeat("external_modules", bh.VtTypeListOfStrings, "external_modules", bh.AzFTString, "dotNetAssembly - list of external modules used."),
	bh.NewVtPathToAzFeat("manifest_resource", bh.VtTypeListOfStrings, "manifest_resource", bh.AzFTString, "dotNetAssembly - list of manifest resources."),
	bh.NewVtPathToAzFeat("metadata_header_rva", bh.VtTypeInteger, "metadata_header_rva", bh.AzFTInteger, "dotNetAssembly - metadata header Relative Virtual Address."),
	bh.NewVtPathToAzFeat("resources_va", bh.VtTypeInteger, "resources_va", bh.AzFTInteger, "dotNetAssembly - resources Virtual Address."),
	// bh.NewVtPathToAzFeat("streams", bh.VtTypeDict, "streams", bh.dont-map, "dotNetAssembly - information about assembly streams, names and associated data. Key is the stream name and value is a dictionary having the following fields:"),
	bh.NewVtPathToAzFeat("streams.chi2", bh.VtTypeFloat, "streams_chi2", bh.AzFTFloat, "dotNetAssembly - chi-squared test value of stream data."),
	bh.NewVtPathToAzFeat("streams.entropy", bh.VtTypeFloat, "streams_entropy", bh.AzFTFloat, "dotNetAssembly - entropy value of stream data."),
	bh.NewVtPathToAzFeat("streams.md5", bh.VtTypeString, "streams_md5", bh.AzFTString, "dotNetAssembly - md5 hash value of stream data."),
	bh.NewVtPathToAzFeat("streams.size", bh.VtTypeInteger, "streams_size", bh.AzFTInteger, "dotNetAssembly - size of stream."),
	bh.NewVtPathToAzFeat("strongname_va", bh.VtTypeInteger, "strongname_va", bh.AzFTInteger, "dotNetAssembly - Relative Virtual Address of the strong name signature hash."),
	bh.NewVtPathToAzFeat("tables_present", bh.VtTypeInteger, "tables_present", bh.AzFTInteger, "dotNetAssembly - number of tables present in the assembly."),
	bh.NewVtPathToAzFeat("tables_rows_map", bh.VtTypeString, "tables_rows_map", bh.AzFTString, "dotNetAssembly - hex representation of number of rows on each table."),
	bh.NewVtPathToAzFeat("tables_rows_map_log", bh.VtTypeString, "tables_rows_map_log", bh.AzFTString, "dotNetAssembly - simplified representation of tables_rows_map."),
	// bh.NewVtPathToAzFeat("type_definition_list", bh.VtTypeListOfDict, "type_definition_list", bh.dont-map, "dotNetAssembly - every entry represents a type definition:"),
	// bh.NewVtPathToAzFeat("type_definition_list.namespace", bh.VtTypeString, "type_definition_list_namespace", bh.AzFTString, "dotNetAssembly - defined types' namespace."),
	// bh.NewVtPathToAzFeat("type_definition_list.type_definitions", bh.VtTypeListOfStrings, "type_definition_list_type_definitions", bh.AzFTString, "dotNetAssembly - defined types."),
	// bh.NewVtPathToAzFeat("unmanaged_method_list", bh.VtTypeListOfDict, "unmanaged_method_list", bh.dont-map, "dotNetAssembly - (optional) list of methods from external modules. Every item in the list contains the following fields:"),
	// bh.NewVtPathToAzFeat("unmanaged_method_list.methods", bh.VtTypeListOfStrings, "unmanaged_method_list_methods", bh.AzFTString, "dotNetAssembly - method names."), // special
	// bh.NewVtPathToAzFeat("unmanaged_method_list.name", bh.VtTypeString, "unmanaged_method_list_name", bh.AzFTString, "dotNetAssembly - module name."),
}

var DotNetAssembly = bh.NewHandlerV3(vtToAzFeatDotNetAssembly, "dot_net_assembly")

/*Merge the features 'major.minor.build.revison' into one string as per microsoft docs - https://learn.microsoft.com/en-us/dotnet/standard/assembly/versioning*/
func mergeVersionInfoHandler(result gjson.Result, featMapping bh.VtPathToAzFeature) ([]events.BinaryEntityFeature, error) {
	resultList := []events.BinaryEntityFeature{}
	oneValueSet := false
	majorVersion := "x"
	minorVersion := "y"
	buildNumb := "z"
	revisionNumb := "a"
	newResult := result.Get(featMapping.VtPath + ".majorversion")
	if newResult.Type != gjson.Null {
		majorVersion = newResult.String()
		oneValueSet = true
	}
	newResult = result.Get(featMapping.VtPath + ".minorversion")
	if newResult.Type != gjson.Null {
		minorVersion = newResult.String()
		oneValueSet = true
	}
	newResult = result.Get(featMapping.VtPath + ".buildnumber")
	if newResult.Type != gjson.Null {
		buildNumb = newResult.String()
		oneValueSet = true
	}
	newResult = result.Get(featMapping.VtPath + ".revisionnumber")
	if newResult.Type != gjson.Null {
		revisionNumb = newResult.String()
		oneValueSet = true
	}
	if !oneValueSet {
		return resultList, nil
	}
	resultList = append(resultList, events.BinaryEntityFeature{
		Name:  featMapping.AzName,
		Value: fmt.Sprintf("%s.%s.%s.%s", majorVersion, minorVersion, buildNumb, revisionNumb),
		Type:  featMapping.AzType,
	})
	return resultList, nil
}

func externalAssembliesHandler(result gjson.Result, featMapping bh.VtPathToAzFeature) ([]events.BinaryEntityFeature, error) {
	resultList := []events.BinaryEntityFeature{}
	newResult := result.Get(featMapping.VtPath)

	if newResult.Type == gjson.Null {
		// Nothing interesting found.
		return resultList, nil
	}

	for packageName, versionData := range newResult.Map() {
		versionNumber := versionData.Get("version").String()
		if len(packageName) > 0 && len(versionNumber) > 0 {
			resultList = append(resultList, events.BinaryEntityFeature{
				Name:  featMapping.AzName,
				Value: packageName,
				Label: versionNumber,
				Type:  featMapping.AzType,
			})
		}
	}
	return resultList, nil
}
