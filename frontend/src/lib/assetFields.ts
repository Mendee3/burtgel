export type AssetFieldOption = { label: string; value: string };
export type AssetFieldDef = {
  key: string;
  label: string;
  required: boolean;
  kind: "text" | "textarea" | "select";
  options?: AssetFieldOption[];
};

const YES_NO: AssetFieldOption[] = [
  { label: "Тийм", value: "Y" },
  { label: "Үгүй", value: "N" },
];

const toOptions = (values: string[]): AssetFieldOption[] => values.map((v) => ({ label: v, value: v }));

export const ASSET_FIELDS: AssetFieldDef[] = [
  { key: "assetName", label: "Хөрөнгийн нэр", required: true, kind: "text" },
  { key: "description", label: "Хөрөнгийн тодорхойлолт", required: true, kind: "textarea" },
  { key: "assetType", label: "Хөрөнгийн төрөл", required: true, kind: "select", options: toOptions(["Цахим", "Биет"]) },
  {
    key: "assetGroupCode",
    label: "Код",
    required: true,
    kind: "select",
    options: toOptions([
      "IDA_CD", "IDA_PII", "IDA_PHI", "IDA_FD", "IDA_SL", "IDA_CF", "IDA_IP",
      "IDA_BD", "IDA_BDoc", "SA_EA", "SA_WA", "SA_OS", "SA_API", "SA_ST",
      "SA_DT", "SA_CVA", "HA_S", "HA_ND", "HA_UD", "HA_SD", "HA_ID",
      "NC_IN", "NC_EC", "NC_VI", "NC_CS", "NC_DS", "NC_NCR",
      "PA_PU", "PA_GU", "PA_D", "PA_E", "PA_CV", "PA_ST",
      "PD_PP", "PD_P", "PD_TM", "PD_ALR", "PD_OC",
    ]),
  },
  { key: "hasPersonalData", label: "Хувь хүний мэдээлэл байгаа эсэх", required: true, kind: "select", options: YES_NO },
  { key: "hasSensitiveData", label: "Эмзэг мэдээлэл байгаа эсэх", required: true, kind: "select", options: YES_NO },
  { key: "owner", label: "Хөрөнгө эзэмшигч", required: true, kind: "text" },
  { key: "custodian", label: "Хөрөнгийн хариуцагч", required: true, kind: "text" },
  { key: "location", label: "Байршил", required: true, kind: "text" },
  { key: "retentionPeriod", label: "Хадгалах хугацаа", required: true, kind: "text" },
  {
    key: "confidentiality",
    label: "Нууцлал",
    required: true,
    kind: "select",
    options: toOptions(["Маш нууц-3", "Нууц-2", "Дотоод хэрэгцээнд-1"]),
  },
  {
    key: "integrityImpact",
    label: "Бүрэн бүтэн байдал алдагдвал үүсэх нөлөөлөл",
    required: true,
    kind: "select",
    options: toOptions(["Өндөр - 3", "Дунд - 2", "Бага - 1"]),
  },
  {
    key: "availabilityImpact",
    label: "Хүртээмжтэй байдал алдагдвал үүсэх нөлөөлөл",
    required: true,
    kind: "select",
    options: toOptions(["Өндөр - 3", "Дунд - 2", "Бага - 1"]),
  },
];

// GraphQL field names (snake_case) as returned by editableFields, mapped to the camelCase keys above.
export const FIELD_KEY_TO_GRAPHQL: Record<string, string> = {
  assetName: "asset_name",
  description: "description",
  assetType: "asset_type",
  assetGroupCode: "asset_group_code",
  hasPersonalData: "has_personal_data",
  hasSensitiveData: "has_sensitive_data",
  owner: "owner",
  custodian: "custodian",
  location: "location",
  retentionPeriod: "retention_period",
  confidentiality: "confidentiality",
  integrityImpact: "integrity_impact",
  availabilityImpact: "availability_impact",
};
