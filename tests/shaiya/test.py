import os
import sys

script_path = os.path.abspath(__file__)
script_root = os.path.dirname(script_path)
project_root = os.path.realpath(script_root + "/../../")

print(project_root)
sys.path.insert(0, project_root)

from offdiff import get_new_addresses, print_addresses, bskip

new_binary = "game-4mb.exe"
old_binary = "game-34mb.exe"
old_addresses = [
        ("SahEncr",         0x0040E00D, 16, 1),    # -> 0x0040e0bd
        ("InvetoryExit_01", 0x0051AAD5, 7, -2),   # -> 0x005186b5
        ("InvetoryExit_02", 0x0051A5C1, 15, -2),   # -> 0x005181a1
        ("CallNB_01",       0x0057BC50, [0xCC, 0x8B11, 0x83EC74, 0x85D2, bskip(6), 0xDB442478], -1),          # -> 0x0057b860  
        ("InvetoryExit_03", 0x00519642,),   
        ("JMPNB_NPCID_01",  0x00519667,),   
        ("JMPNB_NPCID_02",  0x0051A503,),   
        ("CallNB_02",       0x00422D40,)
]


output = get_new_addresses(old_addresses, os.path.join(script_root, old_binary), os.path.join(script_root, new_binary))

print_addresses(output)

print(output)

assert(output["SahEncr"].candidates[0] == 0x0040e0bd)
assert(output["InvetoryExit_01"].candidates[0] == 0x005186b5)
assert(output["InvetoryExit_02"].candidates[0] == 0x005181a1)

assert(1 == len(output["SahEncr"].candidates))
assert(1 == len(output["InvetoryExit_01"].candidates))
assert(1 == len(output["InvetoryExit_02"].candidates))

exit(0)

my_addrs = [
        ("SahEncrypt",             0x0040E00D),
        ("InvetoryExit_01",        0x0051AAD5),
        ("SahEncrypt",             0x0040E00D),
        ("InvetoryExit_01",        0x0051AAD5),       
        ("InvetoryExit_02",        0x0051A5C1),       
        ("CallNB_01",              0x0057BC50),        
        ("InvetoryExit_03",        0x00519642),    
        ("JMPNB_NPCID_01",         0x00519667),
        ("JMPNB_NPCID_02",         0x0051A503),
        ("CallNB_02",              0x00422D40),
        ("opensettingjmp",         0x0051BA91),
        ("renderjmp",              0x0051F5A2),
        ("renderpacketall",        0x00552520),
        ("clickjmp",               0x00521C3B),
        ("clickjnejmp",            0x00521D31),
        ("clickpacketcall",        0x00550B00),
        
        ("savejmp",                0x0051BDE6),
        ("saveinj",                0x007C0E14),
        ("saveinj2",               0x007C0E1C),
        ("savewrite",              0x7462EC),
 
        ("bindbuttonpositionjmp",    0x0051ED40),
        ("bindbuttonpositionpacketall",    0x00550950),
        
        ("cReturn1",    0x477EF7),
        ("cReturn2",    0x477F69),
        ("cReturn3",    0x477FF1),
        ("cReturn4",    0x47807D),
        ("cReturn5",    0x478109),
        ("cReturn7",    0x4759B8),
        ("cReturn8",    0x475A0A),
        ("cPosx",       0x631AB0),
        ("cReturn9",    0x47599E),
        ("desativar",   0x59FBC5),
        ("saida7",      0x0043B1DB),
        ("saida6",      0x43AB66),
        ("nameReturn",  0x59FBB4),
        ("original",    0x914490),
        ("nameReturn2", 0x478592),
        ("return2",     0x59F965),
        ("saida8",      0x439F26),
        ("saida9",      0x004394AC),
        ("saida1",      0x439F26),
        ("rev",         0x439F26),
        ("rev2",        0x43B676),
      #  ("rev3",        0x43AC7A7),
        ("saidaaa",     0x43A0CA),
        ("saida35",     0x0439F33),
        ("remover",     0x004394AE),
        ("retornooo",   0x439F39),
        ("pet50",       0x00439F26),
        ("pet51",       0x004394BB),
        ("oculto",      0x0043A0CA),
        ("wingoff",     0x087D263),
        ("Comand_imput",0x632BD7),
        ("Cmd_retorno", 0x4864C6),
        ("ocultoasa1",  0x0041F505),
        ("Asa3return",  0x0041F4DA),
        ("returnasa4",  0x0041F5A5),
        ("returnpet5",  0x00439F26),
        ("cmd_jump",    0x04871D2),
        ("removerasa",  0x0041F76D),
        ("mensagem",    0x0422D40),
        ("retorno",     0x41627D),
        ("petret1",     0x04112AB),
        ("petret2",     0x004112AB),
        ("petre1",      0x04112C0),
        ("petre2",      0x00418310),
        ("returnpet3",  0x0041814E),
        ("returnpet4",  0x00411228),
        ("return3",     0x59F968),
        ("cGetCall",    0x0057B950),
        ("cAllocReturn",0x0044F5D9),
        ("Display_HP_Bar", 0x0057C3F0),
        ("Send_Pos", 0x00631AB0),
        ("Return_HP_Bar", 0x0045385A),
        ("dwIconRender", 0x04B7170),
        ("dwBagRetn", 0x51A6A7),
        ("dwBarRtn", 0x0501317),
        ("dwEquipRetn", 0x0051A8BA),
        ("x10Return", 0x005298A0),
        ("x10Return2", 0x00529896),
        ("x10Block", 0x005298AF),
        ("x10Return3", 0x005298A5),
        ("x10block2", 0x5298AF),
        ("dwx10return", 0x00529886),
        ("skillbarnew6jmp", 0x0042B4FB),
        ("skillbarnew6call1", 0x006306C3),
        ("skillbarnew6call2", 0x004FFBC0),
        
        
        ("skillbar_add1jmp", 0x004A3E28),	("skillbar_add1jnejmp", 0x004A3E04),
        ("skillbar_add1call", 0x004FF6C0),	("skillbar_add2jmp", 0x004A3F0B),
        ("skillbar_add2call", 0x004FF6C0),	("skillbar_add3jmp", 0x004FFCA2),
        ("skillbar_add3jejmp", 0x004FFCB7),	("skillbar_add4jmp", 0x005008C0),
        ("skillbar_add4jejmp", 0x00500A6D),	("skillbar_add5jmp", 0x00500F79),
        ("skillbar_add5jajmp", 0x00500FC5),	("skillbar_add6jmp", 0x00500FBB),
        ("skillbar_add7jmp", 0x00501497),	("skillbar_add7jejmp", 0x050155C),
        ("skillbar_add7jnejmp", 0x005015AE),	("RaidInj1jmp", 0x53F229),
        ("RaidInj2jmp", 0x53FEDD),	("RaidInj4jmp", 0x5410EB),	("RaidInj4call", 0x451840),
        ("RaidInj5jmp", 0x54000F),	("RaidInj5call", 0x451840),	("RaidInj6jmp", 0x4A42E0),
        ("RaidInj6exjmp", 0x4A4949),	("RaidInj6jgc", 0x4A470F),	("RaidInj7jmp", 0x48D9A3),
        ("RaidInj7call", 0x48D4A0),	("RaidInj8jmp", 0x48D9A3),	("RaidInj8call", 0x48D4A0),
        ("RaidInj9jmp", 0x53DE78),	("RaidInj10jmp", 0x53DECE),	("RaidInj10call", 0x573FF0),
        ("RaidInj11jmp", 0x445D70),	("RaidInj12jmp", 0x53D771),	("RaidInj12r1", 0x022AA750),
        ("RaidInj12r3", 0x0227E338),	("RaidInj14jmp", 0x53F32B),	("RaidInj14call", 0x451840),
        ("RaidInj15jmp", 0x540D79),	("Send_Use_Item", 0x005EBB40),	("SendPacketAddr", 0x005EA9F0),
        ("dwExitSetModelID", 0x004E5B47),	("dwContinueSetModelID", 0x004E5CA6),	("dwAllowModelsJne", 0x004144CE),
        ("dwExitAllowModels", 0x0041431D),	("dwSuccessAllowModels", 0x00414872),	("dwOriginalCallSetPositionFunc", 0x00659391),
        ("dwExitSetPosition", 0x004148CE),	("dwExitGetPacket", 0x005F440C),	("dwExitCommand", 0x00486B09),
        ("dwCommandCheck", 0x00632BD7),	("dwExitChangeMountSpeed", 0x0041A581),	("dwFlashReturn", 0x00427C06),
        ("dwExitEquip", 0x005190DF),	("dwExitSetCorrectSlotByType", 0x0059FBAE),	("dwExitItemRemove", 0x00518BDF),
        ("dwAllowItemRemove", 0x00518C79),	("dwExitRemoveStackText", 0x004E6B37),	("dwRemoveTypeEffectJe", 0x00519498),
        ("dwExitRemoveTypeEffect", 0x00519078),	("dwExitSetSlotIconSize", 0x005180D7),	("dwExitFixBag1BtnA", 0x00519BC0),
        ("dwExitFixBag1BtnB", 0x0051A2A4),	("dwExitFixBag2BtnA", 0x0051A2B7),	("dwExitFixBag2BtnB", 0x0051A2CA),
        ("dwExitSetSlotIconPosition", 0x0051A7F7),	("dwNotShowA", 0x005268BB),	("dwExitShowSkillA", 0x00526200),
        ("dwExitShowSkillB", 0x00527139),	("dwNotShowB", 0x005273AE),	("dwExitFixBag2BtnC", 0x00519BD3),
        ("dwExitFixBag2BtnD", 0x00519BE9),	("dwShowColor", 0x00453539),	("Retorno", 0x004534C2),
        ("Retorno2", 0x004534CB),	("Country", 0x22AA816),	("cColorReturn", 0x00453526),
        ("Return_Color", 0x00453539),	("Remove_Traje_Effect", 0x00416830),	("dwEffrtn", 0x0058F8A5),
        ("Remove_Effect", 0x00416830),	("Send_Load_Effect", 0x0058CC40),	("Alloc_Return", 0x0042BBB4),
        ("Effect_Address", 0x0042BA77),	("Effect_Equip_Return", 0x0059FBA4),	("Render_Effect", 0x0041A100),
        ("Respawn_Return", 0x005EB8C5),	("Respawn_Return_2", 0x00595C6A),



        ("Effect_Map_Return", 0x00416225),
        ("SendPos", 0x00631AB0),
        ("SendDisplay", 0x0057BA70),
        ("cDisplayReturn", 0x00453984),
        ("cPacketProtectReturn", 0x005EA9F5),
        ("cHideGsConfigReturn", 0x0060AC7E),
        ("cZoomLimitReturn", 0x00442933),
        ("sahRet", 0x0040E00D),
        ("sahCall", 0x006339E6),
        ("cPacketReturn", 0x005EC7A4),
        ("enchan_retn", 0x4B8690),
        ("newranksposjmp", 0x0044E914),
        ("newrankspos2jmp", 0x0044E89D),
        ("newrankpointjmp", 0x0044E887),
        ("cBoostReturn", 0x005812C6),
        ("cBoostRemoveLayer", 0x0058135E),
        ("cSendSmall", 0x0057BD80),
        ("cStopFuncAddr", 0x004B5822),
        ("cSmallReturn", 0x004B5815),
        ("cSmallReturn2", 0x004B57E7),
        ("cStackReturn", 0x004D8AED),
        ("cWhiteReturn", 0x004D8AD8),
        ("cAjustTimeReturn", 0x004B6B68),
        ("cAjustTime2Return", 0x004B6B23),
        ("cAjustMenssageReturn", 0x004D8AAB),
        ("cAllocTitleOriginal", 0x0044F5D0),
        ("SahEncryptOriginal", 0x0040E008),
        ("AllocEffectsOriginal", 0x0042BBAA),
        ("cSmallIcon", 0x4B57E2),
        ("cStack", 0x4D8AE7),
        ("cWhiteSmall", 0x4D8AD3),
        ("cAjustTime", 0x4B6B62),
        ("cAjustTime2", 0x4B6B1C),
        ("cAjustMenssage", 0x4D8AA2),
        ("cProtectPacket", 0x005EC79F),
        ("enchantt_dmg", 0x4B867F),
        ("HP_Bar_Main", 0x00453853),
        ("Equip", 0x0051A8A3),
        ("Bar", 0x00501303),
        ("Bag", 0x51A68D),
        ("skillbar_main", 0x0042B4F5),
        ("skillbar_add1", 0x004A3E21),
        ("skillbar_add2", 0x004A3F03),
        ("skillbar_add3", 0x004FFC9C),
        ("skillbar_add4", 0x005008BB),
        ("skillbar_add5", 0x00500F70),
        ("skillbar_add6", 0x00500FB4),
        ("skillbar_add7", 0x00501490),
        ("skillbar_main_memory2", 0x00500559),
        ("dwX10Stat", 0x0052987D),
        ("x10stats3", 0x005298A0),
        ("x10stats2", 0x00529890),
        ("x10stats", 0x00529898),
        ("cPacketProtect", 0x005EA9F0),
        ("cZoomLimit", 0x0044292D),
        ("Raidtextcolor1", 0x53DF65),
        ("Raidtextcolor2", 0x53E005),
        ("RaidInj1", 0x53F223),
        ("RaidInj2", 0x53FED7),
        ("RaidInjAdr3", 0x4EDDD1),
        ("RaidInj4", 0x5410E2),
        ("RaidInj5", 0x540006),
        ("RaidInj6", 0x4A42DA),
        ("RaidInj7", 0x48D977),
        ("RaidInj8", 0x48D916),
        ("RaidInj9", 0x53DE72),
        ("RaidInj10", 0x53DEC5),
        ("RaidInj11", 0x445D67),
        ("RaidInj12", 0x53D76B),
        ("RaidInjAdr13", 0x53D748),
        ("RaidInj14", 0x53F322),
        ("RaidInj15", 0x540D73),
        ("asa", 0x43AB5F),
        ("asa2", 0x43B1D4),
        ("comando", 0x4864C1),
        ("pet1", 0x004112A5),
        ("pet3", 0x00418146),
        ("pet4", 0x00411222),
        ("pet5", 0x00439F1F),
        ("asa4", 0x0041F59D),
        ("asa3", 0x0041F4D3),
        ("WriteBytes", 0x004E5B44),
        ("SetModelID", 0x004E5B3E),
        ("SetPosition", 0x004148C7),
        ("AllowModels", 0x00414315),
        ("GetPacket", 0x005F4405),
        ("Command", 0x00486B02),
        ("ChangeMountSpeed", 0x0041A57B),
        ("flash", 0x427C00),
        ("bySlotCap", 0x005190E1),
        ("ItemEquip", 0x005190D9),
        ("SetCorrectSlotByType", 0x0059FBA6),
        ("ItemRemove", 0x00518BD7),
        ("RemoveStackText", 0x004E6B30),
        ("RemoveTypeEffect", 0x00519070),
        ("SetSlotIconSize", 0x005180D0),
        ("FixBag1BtnA", 0x00519BBA),
        ("FixBag1BtnB", 0x0051A29E),
        ("FixBag2BtnA", 0x0051A2B1),
        ("FixBag2BtnB", 0x0051A2C4),
        ("FixBag2BtnC", 0x00519BCD),
        ("FixBag2BtnD", 0x00519BE3),
        ("SetSlotIconPosition", 0x0051A7F0),

        ("cSmallIcon", 0x004B57E2),
        ("cStack", 0x004D8AE7),
        ("cWhiteSmall", 0x004D8AD3),
        ("cAjustTime", 0x004B6B62),
        ("cAjustTime2", 0x004B6B1C),
        ("cAjustMenssage", 0x004D8AA2),
        ("cProtectPacket", 0x005EC79F),
        ("enchantt_dmg", 0x004B867F),
        ("HP_Bar_Main", 0x00453853),
        ("Equip", 0x0051A8A3),
        ("Bar", 0x00501303),
        ("Bag", 0x0051A68D),
        ("skillbar_main", 0x0042B4F5),
        ("skillbar_add1", 0x004A3E21),
        ("skillbar_add2", 0x004A3F03),
        ("skillbar_add3", 0x004FFC9C),
        ("skillbar_add4", 0x005008BB),
        ("skillbar_add5", 0x00500F70),
        ("skillbar_add6", 0x00500FB4),
        ("skillbar_add7", 0x00501490),
        ("skillbar_main_memory2", 0x00500559),
        ("dwX10Stat", 0x0052987D),
        ("x10stats3", 0x005298A0),
        ("x10stats2", 0x00529890),
        ("x10stats", 0x00529898),
        ("cPacketProtect", 0x005EA9F0),
        ("cZoomLimit", 0x0044292D),
        ("Raidtextcolor1", 0x0053DF65),
        ("Raidtextcolor2", 0x0053E005),
        ("RaidInj1", 0x0053F223),
        ("RaidInj2", 0x0053FED7),
        ("RaidInjAdr3", 0x004EDDD1),
        ("RaidInj4", 0x005410E2),
        ("RaidInj5", 0x00540006),
        ("RaidInj6", 0x004A42DA),
        ("RaidInj7", 0x0048D977),
        ("RaidInj8", 0x0048D916),
        ("RaidInj9", 0x0053DE72),
        ("RaidInj10", 0x0053DEC5),
        ("RaidInj11", 0x00445D67),
        ("RaidInj12", 0x0053D76B),
        ("RaidInjAdr13", 0x0053D748),
        ("RaidInj14", 0x0053F322),
        ("RaidInj15", 0x00540D73),
        ("asa", 0x0043AB5F),
        ("asa2", 0x0043B1D4),
        ("comando", 0x004864C1),
        ("pet1", 0x004112A5),
        ("pet3", 0x00418146),
        ("pet4", 0x00411222),
        ("pet5", 0x00439F1F),
        ("asa4", 0x0041F59D),
        ("asa3", 0x0041F4D3),
        ("SetModelID", 0x004E5B3E),
        ("WriteBytes", 0x004E5B44), 
        ("SetPosition", 0x004148C7),
        ("AllowModels", 0x00414315),
        ("GetPacket", 0x005F4405),
        ("Command", 0x00486B02),
        ("ChangeMountSpeed", 0x0041A57B),
        ("flash", 0x00427C00),
        ("bySlotCap", 0x005190E1), 
        ("bySlotCap", 0x0051A1D0),
        ("bySlotCap", 0x0051A9B8),
        ("bySlotCap", 0x00518B5C), 
        ("ItemEquip", 0x005190D9),
        ("SetCorrectSlotByType", 0x0059FBA6),
        ("ItemRemove", 0x00518BD7),
        ("RemoveStackText", 0x004E6B30),
        ("RemoveTypeEffect", 0x00519070),
        ("SetSlotIconSize", 0x005180D0),
        ("FixBag1BtnA", 0x00519BBA),
        ("FixBag1BtnB", 0x0051A29E),
        ("FixBag2BtnA", 0x0051A2B1),
        ("FixBag2BtnB", 0x0051A2C4),
        ("FixBag2BtnC", 0x00519BCD),
        ("FixBag2BtnD", 0x00519BE3),
        ("SetSlotIconPosition", 0x0051A7F0),
        ("unknown_1", 0x0053B571), 
        ("unknown_2", 0x0053B5D7),
        ("unknown_3", 0x00519D92), 
        ("dwColor", 0x004534BC),
        ("dwEffects", 0x0058F8A0),
        ("cDisplayTitle", 0x0045397D),
        ("onff", 0x00416273),
        ("conff", 0x0059F960),
        ("wwwconf", 0x0047858C),
        ("wwconf", 0x0059FBAE),
        ("dwCharacterScreen", 0x00477EF2),
        ("dwCharacterScreen2", 0x00477F64),
        ("dwCharacterScreen3", 0x00477FEC),
        ("dwCharacterScreen4", 0x00478078),
        ("dwCharacterScreen5", 0x00478104),
        ("dwCharacterScreen7", 0x004759B3),
        ("dwCharacterScreen8", 0x00475A01),
        ("dwCharacterScreen9", 0x00475996),
        ("InvetoryBytes_01", 0x0051959E), 
        ("Invetory_03", 0x005195A4),
        ("Effect_Costume", 0x0059FB9E),
        ("Show_Effect_When_Respawn", 0x005EB8C0),
        ("Show_Effect_When_Respawn_2", 0x00595C62),
        ("Effect_When_Change_Map", 0x00416220),
        ("opensetting", 0x0051BA8B),
        ("render", 0x0051F59D),
        ("click", 0x00521C35),
        ("save", 0x0051BDE0),
        ("bindbuttonposition", 0x0051ED3B),
        ("optionokbutton", 0x0051ED2B), 
        ("optioncancelbutton", 0x0051ED40),
        ("optionresetbutton", 0x0051ED55),
        ("cFpsBoost", 0x005812C0),
        ("gradesize", 0x0044F684), 
        ("newrankspos", 0x0044E90E),
        ("newrankspos2", 0x0044E897),
        ("newrankpoint", 0x0044E880),
        ("ranklimit", 0x0044E873) 
]

addrs = []
for x in my_addrs:
        addrs.append([x[1]])
        
output = get_new_addresses(addrs, os.path.join(script_root, old_binary), os.path.join(script_root, new_binary))

print_addresses(output)



# Initialize counts
empty_count = 0
one_element_count = 0
multiple_elements_count = 0

# Iterate through the array and categorize the subarrays
for subarray in output:
    if len(subarray) == 0:
        empty_count += 1
    elif len(subarray) == 1:
        one_element_count += 1
    elif len(subarray) > 1:
        multiple_elements_count += 1

# Calculate proportions
total_count = len(output)
empty_proportion = empty_count / total_count
one_element_proportion = one_element_count / total_count
multiple_elements_proportion = multiple_elements_count / total_count

# Pretty print the results
from pprint import pprint

# Preparing the result dictionary
result = {
    "Empty arrays []": {
        "Count": empty_count,
        "Proportion": f"{empty_proportion:.2%}"
    },
    "Arrays with one element [int]": {
        "Count": one_element_count,
        "Proportion": f"{one_element_proportion:.2%}"
    },
    "Arrays with multiple elements [multiple]": {
        "Count": multiple_elements_count,
        "Proportion": f"{multiple_elements_proportion:.2%}"
    }
}

# Pretty print the result
pprint(result)
