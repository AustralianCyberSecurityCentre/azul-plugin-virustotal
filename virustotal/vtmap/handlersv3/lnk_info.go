package handlersv3

import (
	bh "github.com/AustralianCyberSecurityCentre/azul-plugin-virustotal.git/virustotal/vtmap/basehandlerv3"
)

var vtToAzFeatLnkInfo = []bh.VtPathToAzFeature{
	bh.NewVtPathToAzFeat("creation_date", bh.VtTypeString, "creation_date", bh.AzFTString, "lnkInfo - date in ISO8601 format."),
	bh.NewVtPathToAzFeat("access_date", bh.VtTypeString, "access_date", bh.AzFTString, "lnkInfo - date in ISO8601 format."),
	bh.NewVtPathToAzFeat("modification_date", bh.VtTypeString, "modification_date", bh.AzFTString, "lnkInfo - date in ISO8601 format."),
	bh.NewVtPathToAzFeat("link_flags", bh.VtTypeListOfStrings, "link_flags", bh.AzFTString, "lnkInfo - basic properties of the LNK file."),
	bh.NewVtPathToAzFeat("target_path", bh.VtTypeString, "target_path", bh.AzFTString, "lnkInfo - (optional) target path from Link Target Identifier fields."),
	bh.NewVtPathToAzFeat("icon_location", bh.VtTypeString, "icon_location", bh.AzFTString, "lnkInfo - (optional) path to the icon location."),
	bh.NewVtPathToAzFeat("mac_address", bh.VtTypeString, "mac_address", bh.AzFTString, "lnkInfo - (optional) network MAC address."),
	bh.NewVtPathToAzFeat("mac_vendor_name", bh.VtTypeString, "mac_vendor_name", bh.AzFTString, "lnkInfo - (optional) network vendor name from MAC address."),
	bh.NewVtPathToAzFeat("machine_id", bh.VtTypeString, "machine_id", bh.AzFTString, "lnkInfo - (optional) computer name."),
	bh.NewVtPathToAzFeat("working_directory", bh.VtTypeString, "working_directory", bh.AzFTString, "lnkInfo - (optional) target working directory."),
	bh.NewVtPathToAzFeat("relative_path", bh.VtTypeString, "relative_path", bh.AzFTString, "lnkInfo - (optional) target file relative path."),
	bh.NewVtPathToAzFeat("command_line_arguments", bh.VtTypeString, "command_line_arguments", bh.AzFTString, "lnkInfo - (optional)."),
	bh.NewVtPathToAzFeat("volume_serial_number", bh.VtTypeString, "volume_serial_number", bh.AzFTString, "lnkInfo - (optional) disk volume serial number."),
	bh.NewVtPathToAzFeat("volume_label", bh.VtTypeString, "volume_label", bh.AzFTString, "lnkInfo - (optional) disk volume label."),
	bh.NewVtPathToAzFeat("local_path", bh.VtTypeString, "local_path", bh.AzFTString, "lnkInfo - (optional)."),
	bh.NewVtPathToAzFeat("common_path", bh.VtTypeString, "common_path", bh.AzFTString, "lnkInfo - (optional)."),
	bh.NewVtPathToAzFeat("network_share_name", bh.VtTypeString, "network_share_name", bh.AzFTString, "lnkInfo - (optional)."),
	// bh.NewVtPathToAzFeat("extra_data.dlt_properties", bh.VtTypeDict, "extra_data_dlt_properties", bh.dont-map, "lnkInfo - dlt properties of the LNK file."),
	bh.NewVtPathToAzFeat("extra_data.dlt_properties.birth_droid_file_id", bh.VtTypeString, "extra_data_dlt_properties_birth_droid_file_id", bh.AzFTString, "lnkInfo - ,"),
	bh.NewVtPathToAzFeat("extra_data.dlt_properties.droid_file_id", bh.VtTypeString, "extra_data_dlt_properties_droid_file_id", bh.AzFTString, "lnkInfo - ,"),
	bh.NewVtPathToAzFeat("extra_data.dlt_properties.birth_droid_volume_id", bh.VtTypeString, "extra_data_dlt_properties_birth_droid_volume_id", bh.AzFTString, "lnkInfo - ,"),
	bh.NewVtPathToAzFeat("extra_data.dlt_properties.droid_volume_id", bh.VtTypeString, "extra_data_dlt_properties_droid_volume_id", bh.AzFTString, "lnkInfo - "),
	// bh.NewVtPathToAzFeat("link_target_id_list", bh.VtTypeListOfDict, "link_target_id_list", bh.dont-map, "lnkInfo - Every entry contains the following fields:"),
	bh.NewVtPathToAzFeat("link_target_id_list.clsid", bh.VtTypeString, "link_target_id_list_clsid", bh.AzFTString, "lnkInfo - ,", bh.AddListOfDictHandling("link_target_id_list", "item_type_str")),
	// bh.NewVtPathToAzFeat("link_target_id_list.item_type", bh.VtTypeInteger, "link_target_id_list_item_type", bh.AzFTInteger, "lnkInfo - ,", bh.AddListOfDictHandling("link_target_id_list", "item_type_str")),
	bh.NewVtPathToAzFeat("link_target_id_list.item_type_str", bh.VtTypeString, "link_target_id_list_item_type_str", bh.AzFTString, "lnkInfo - ", bh.AddListOfDictHandling("link_target_id_list", "item_type_str")),
	// bh.NewVtPathToAzFeat("header", bh.VtTypeDict, "header", bh.dont-map, "lnkInfo - ."),
	bh.NewVtPathToAzFeat("header.show_window", bh.VtTypeInteger, "header_show_window", bh.AzFTInteger, "lnkInfo - ,"),
	bh.NewVtPathToAzFeat("header.show_window_str", bh.VtTypeString, "header_show_window_str", bh.AzFTString, "lnkInfo - ,"),
	bh.NewVtPathToAzFeat("header.hot_key", bh.VtTypeString, "header_hot_key", bh.AzFTString, "lnkInfo - ,"),
	bh.NewVtPathToAzFeat("header.file_size", bh.VtTypeInteger, "header_file_size", bh.AzFTInteger, "lnkInfo - "),
}

var LnkInfo = bh.NewHandlerV3(vtToAzFeatLnkInfo, "lnk_info")
