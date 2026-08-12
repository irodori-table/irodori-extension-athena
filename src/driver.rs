use std::collections::{BTreeMap, HashMap};
use std::sync::{Mutex, OnceLock};
use std::time::Duration;

use aws_config::BehaviorVersion;
use aws_credential_types::Credentials;
use aws_sdk_athena::types::{QueryExecutionContext, QueryExecutionState, ResultConfiguration};
use aws_sdk_athena::Client;
use aws_types::region::Region;
use serde_json::{json, Map, Value};
use tokio::runtime::Runtime;

use crate::abi::{self, IrodoriConnectorBuffer};
use crate::{ABI_VERSION, CONFIG_JSON, DRIVER_LINKED, ENGINE, MANIFEST_JSON};

static CONNECTIONS: OnceLock<Mutex<HashMap<String, AthenaConnection>>> = OnceLock::new();
static RUNTIME: OnceLock<Runtime> = OnceLock::new();

#[derive(Clone)]
struct AthenaConnection {
    client: Client,
    config: AthenaConfig,
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct AthenaConfig {
    region: String,
    endpoint: Option<String>,
    profile: Option<String>,
    credentials: Option<AwsCredentials>,
    workgroup: String,
    database: Option<String>,
    catalog: Option<String>,
    output_location: Option<String>,
    redaction_values: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct AwsCredentials {
    access_key_id: String,
    secret_access_key: String,
    session_token: Option<String>,
}

#[derive(Default)]
struct ObjectMeta {
    columns: Vec<Value>,
}

type QueryRows = Vec<Vec<Value>>;
type QueryOutput = (Vec<String>, QueryRows, bool);

fn connections() -> &'static Mutex<HashMap<String, AthenaConnection>> {
    CONNECTIONS.get_or_init(|| Mutex::new(HashMap::new()))
}

fn runtime() -> Result<&'static Runtime, String> {
    if let Some(runtime) = RUNTIME.get() {
        return Ok(runtime);
    }
    let runtime = Runtime::new().map_err(|err| format!("create tokio runtime failed: {err}"))?;
    let _ = RUNTIME.set(runtime);
    RUNTIME
        .get()
        .ok_or_else(|| "create tokio runtime failed.".to_string())
}

pub fn call_json(request: IrodoriConnectorBuffer) -> IrodoriConnectorBuffer {
    let request = match abi::parse_request(request) {
        Ok(request) => request,
        Err(response) => return response,
    };
    let method = match abi::request_method(request.as_ref()) {
        Ok(method) => method,
        Err(response) => return response,
    };

    match method {
        "health" | "ping" => abi::ok(Map::from_iter([
            ("engine".to_string(), Value::String(ENGINE.to_string())),
            ("abiVersion".to_string(), json!(ABI_VERSION)),
            ("driverLinked".to_string(), Value::Bool(DRIVER_LINKED)),
        ])),
        "describe" | "capabilities" => abi::ok(Map::from_iter([
            ("engine".to_string(), Value::String(ENGINE.to_string())),
            ("abiVersion".to_string(), json!(ABI_VERSION)),
            ("driverLinked".to_string(), Value::Bool(DRIVER_LINKED)),
            (
                "manifest".to_string(),
                serde_json::from_str(MANIFEST_JSON).unwrap_or(Value::Null),
            ),
            (
                "config".to_string(),
                serde_json::from_str(CONFIG_JSON).unwrap_or(Value::Null),
            ),
        ])),
        "manifest" => abi::owned_buffer(MANIFEST_JSON.to_string()),
        "config" => abi::owned_buffer(CONFIG_JSON.to_string()),
        "connect" => connect(request.as_ref().expect("connect has request")),
        "query" => query(request.as_ref().expect("query has request")),
        "metadata" => metadata(request.as_ref().expect("metadata has request")),
        "close" => close(request.as_ref().expect("close has request")),
        other => abi::error(
            "connector.unknownMethod",
            format!("unknown connector method: {other}"),
        ),
    }
}

fn connect(request: &Value) -> IrodoriConnectorBuffer {
    let connection_id = abi::connection_id(Some(request));
    let config = match AthenaConfig::from_request(request) {
        Ok(config) => config,
        Err(err) => return abi::error("connector.invalidRequest", err),
    };
    let connection =
        match runtime().and_then(|runtime| runtime.block_on(AthenaConnection::new(config))) {
            Ok(connection) => connection,
            Err(err) => return abi::error("connector.connectFailed", err),
        };
    let workgroup_state = match runtime()
        .and_then(|runtime| runtime.block_on(probe_connection(&connection)))
    {
        Ok(workgroup_state) => workgroup_state,
        Err(err) => return abi::error("connector.connectFailed", connection.config.redact(&err)),
    };

    let mut guard = match connections().lock() {
        Ok(guard) => guard,
        Err(_) => {
            return abi::error(
                "connector.statePoisoned",
                "Connector connection state is poisoned.",
            )
        }
    };
    let mut response = Map::from_iter([
        ("engine".to_string(), Value::String(ENGINE.to_string())),
        (
            "connectionId".to_string(),
            Value::String(connection_id.clone()),
        ),
        ("driverLinked".to_string(), Value::Bool(DRIVER_LINKED)),
        (
            "region".to_string(),
            Value::String(connection.config.region.clone()),
        ),
        (
            "workgroup".to_string(),
            Value::String(connection.config.workgroup.clone()),
        ),
        ("workgroupState".to_string(), Value::String(workgroup_state)),
    ]);
    if let Some(database) = connection.config.database.as_deref() {
        response.insert("database".to_string(), Value::String(database.to_string()));
    }
    if let Some(catalog) = connection.config.catalog.as_deref() {
        response.insert("catalog".to_string(), Value::String(catalog.to_string()));
    }
    guard.insert(connection_id, connection);
    abi::ok(response)
}

fn query(request: &Value) -> IrodoriConnectorBuffer {
    let connection_id = abi::connection_id(Some(request));
    let Some(sql) = abi::string_field(request, "sql")
        .or_else(|| abi::string_field(request, "query"))
        .or_else(|| abi::string_field(request, "statement"))
    else {
        return abi::error(
            "connector.invalidRequest",
            "query requires a string sql, query, or statement field.",
        );
    };
    let connection = match connection(&connection_id) {
        Ok(connection) => connection,
        Err(response) => return response,
    };
    match runtime()
        .and_then(|runtime| runtime.block_on(run_query(&connection, sql, abi::max_rows(request))))
    {
        Ok((columns, rows, truncated)) => abi::ok(Map::from_iter([
            ("connectionId".to_string(), Value::String(connection_id)),
            (
                "columns".to_string(),
                Value::Array(columns.into_iter().map(Value::String).collect()),
            ),
            (
                "rows".to_string(),
                Value::Array(rows.into_iter().map(Value::Array).collect()),
            ),
            ("truncated".to_string(), Value::Bool(truncated)),
        ])),
        Err(err) => abi::error("connector.queryFailed", connection.config.redact(&err)),
    }
}

fn metadata(request: &Value) -> IrodoriConnectorBuffer {
    let connection_id = abi::connection_id(Some(request));
    let connection = match connection(&connection_id) {
        Ok(connection) => connection,
        Err(response) => return response,
    };
    match runtime().and_then(|runtime| runtime.block_on(load_metadata(&connection))) {
        Ok(metadata) => abi::ok(Map::from_iter([
            ("connectionId".to_string(), Value::String(connection_id)),
            ("metadata".to_string(), metadata),
        ])),
        Err(err) => abi::error("connector.metadataFailed", connection.config.redact(&err)),
    }
}

fn close(request: &Value) -> IrodoriConnectorBuffer {
    let connection_id = abi::connection_id(Some(request));
    let mut guard = match connections().lock() {
        Ok(guard) => guard,
        Err(_) => {
            return abi::error(
                "connector.statePoisoned",
                "Connector connection state is poisoned.",
            )
        }
    };
    let existed = guard.remove(&connection_id).is_some();
    abi::ok(Map::from_iter([
        ("connectionId".to_string(), Value::String(connection_id)),
        ("closed".to_string(), Value::Bool(existed)),
    ]))
}

impl AthenaConnection {
    async fn new(config: AthenaConfig) -> Result<Self, String> {
        let mut loader = aws_config::defaults(BehaviorVersion::latest())
            .region(Region::new(config.region.clone()));
        if let Some(profile) = config.profile.as_deref() {
            loader = loader.profile_name(profile);
        }
        if let Some(credentials) = config.credentials.as_ref() {
            loader = loader.credentials_provider(Credentials::new(
                credentials.access_key_id.clone(),
                credentials.secret_access_key.clone(),
                credentials.session_token.clone(),
                None,
                "irodori-athena",
            ));
        }
        let shared_config = loader.load().await;
        let mut builder = aws_sdk_athena::config::Builder::from(&shared_config);
        if let Some(endpoint) = config.endpoint.as_deref() {
            builder = builder.endpoint_url(endpoint);
        }
        let client = Client::from_conf(builder.build());
        Ok(Self { client, config })
    }
}

impl AthenaConfig {
    fn from_request(request: &Value) -> Result<Self, String> {
        let region = option_string(request, &["region", "awsRegion"])
            .or_else(|| std::env::var("AWS_REGION").ok())
            .or_else(|| std::env::var("AWS_DEFAULT_REGION").ok())
            .or_else(|| profile_region(request))
            .ok_or_else(|| "Athena requires an AWS region.".to_string())?;
        let endpoint = option_string(
            request,
            &[
                "endpoint",
                "endpointUrl",
                "endpointURL",
                "url",
                "connectionString",
                "dsn",
            ],
        )
        .map(|value| normalize_endpoint(&value, &region));
        let profile = option_string(request, &["profile", "awsProfile"])
            .or_else(|| form_profile_name(request))
            .or_else(|| std::env::var("AWS_PROFILE").ok());
        let credentials = credentials_from_request(request).or_else(env_credentials);
        let workgroup = option_string(request, &["workgroup", "workGroup", "workGroupName"])
            .unwrap_or_else(|| "primary".to_string());
        let database = option_string(request, &["database", "db", "schema"]);
        let catalog = option_string(request, &["catalog", "dataCatalog"]);
        let output_location = option_string(
            request,
            &[
                "outputLocation",
                "s3OutputLocation",
                "queryResultsLocation",
                "resultsLocation",
            ],
        )
        .or_else(|| std::env::var("ATHENA_OUTPUT_LOCATION").ok());
        let mut redaction_values = Vec::new();
        if let Some(endpoint) = endpoint.as_deref() {
            collect_url_auth(endpoint, &mut redaction_values);
        }
        if let Some(output_location) = output_location.as_deref() {
            collect_url_auth(output_location, &mut redaction_values);
        }
        if let Some(credentials) = credentials.as_ref() {
            push_sensitive(&mut redaction_values, Some(&credentials.access_key_id));
            push_sensitive(&mut redaction_values, Some(&credentials.secret_access_key));
            push_sensitive(&mut redaction_values, credentials.session_token.as_deref());
        }
        Ok(Self {
            region,
            endpoint,
            profile,
            credentials,
            workgroup,
            database,
            catalog,
            output_location,
            redaction_values,
        })
    }

    fn redact(&self, message: &str) -> String {
        let endpoint = self.endpoint.as_deref().unwrap_or_default();
        self.redaction_values.iter().fold(
            message.replace(endpoint, "<athena-endpoint>"),
            |message, secret| {
                if secret.is_empty() {
                    message
                } else {
                    message.replace(secret, "****")
                }
            },
        )
    }
}

async fn probe_connection(connection: &AthenaConnection) -> Result<String, String> {
    let response = connection
        .client
        .get_work_group()
        .work_group(&connection.config.workgroup)
        .send()
        .await
        .map_err(|err| format!("Athena GetWorkGroup failed: {err}"))?;
    Ok(response
        .work_group()
        .and_then(|workgroup| workgroup.state())
        .map(|state| state.as_str().to_string())
        .unwrap_or_else(|| "UNKNOWN".to_string()))
}

async fn run_query(
    connection: &AthenaConnection,
    sql: &str,
    cap: usize,
) -> Result<QueryOutput, String> {
    let query_execution_id = start_query(connection, sql).await?;
    wait_for_query(connection, &query_execution_id).await?;
    fetch_results(connection, &query_execution_id, cap).await
}

async fn start_query(connection: &AthenaConnection, sql: &str) -> Result<String, String> {
    let mut builder = connection
        .client
        .start_query_execution()
        .query_string(sql)
        .work_group(&connection.config.workgroup);
    let mut context_builder = QueryExecutionContext::builder();
    if let Some(database) = connection.config.database.as_deref() {
        context_builder = context_builder.database(database);
    }
    if let Some(catalog) = connection.config.catalog.as_deref() {
        context_builder = context_builder.catalog(catalog);
    }
    builder = builder.query_execution_context(context_builder.build());
    if let Some(output_location) = connection.config.output_location.as_deref() {
        builder = builder.result_configuration(
            ResultConfiguration::builder()
                .output_location(output_location)
                .build(),
        );
    }
    let response = builder
        .send()
        .await
        .map_err(|err| format!("Athena StartQueryExecution failed: {err}"))?;
    response
        .query_execution_id()
        .map(str::to_string)
        .ok_or_else(|| "Athena StartQueryExecution did not return query_execution_id.".to_string())
}

async fn wait_for_query(
    connection: &AthenaConnection,
    query_execution_id: &str,
) -> Result<(), String> {
    for _ in 0..300 {
        let response = connection
            .client
            .get_query_execution()
            .query_execution_id(query_execution_id)
            .send()
            .await
            .map_err(|err| format!("Athena GetQueryExecution failed: {err}"))?;
        let status = response
            .query_execution()
            .and_then(|execution| execution.status());
        match status.and_then(|status| status.state()) {
            Some(QueryExecutionState::Succeeded) => return Ok(()),
            Some(QueryExecutionState::Failed) | Some(QueryExecutionState::Cancelled) => {
                let reason = status
                    .and_then(|status| status.state_change_reason())
                    .unwrap_or("Athena query failed.");
                return Err(reason.to_string());
            }
            _ => tokio::time::sleep(Duration::from_secs(1)).await,
        }
    }
    Err("Athena query did not finish before polling timeout.".to_string())
}

async fn fetch_results(
    connection: &AthenaConnection,
    query_execution_id: &str,
    cap: usize,
) -> Result<QueryOutput, String> {
    let mut columns = Vec::new();
    let mut rows = Vec::new();
    let mut next_token = None;
    let mut first_page = true;
    loop {
        let mut builder = connection
            .client
            .get_query_results()
            .query_execution_id(query_execution_id)
            .max_results(1000);
        if let Some(token) = next_token.take() {
            builder = builder.next_token(token);
        }
        let response = builder
            .send()
            .await
            .map_err(|err| format!("Athena GetQueryResults failed: {err}"))?;
        if columns.is_empty() {
            columns = response
                .result_set()
                .and_then(|set| set.result_set_metadata())
                .map(|metadata| {
                    metadata
                        .column_info()
                        .iter()
                        .map(|column| column.name().to_string())
                        .collect::<Vec<_>>()
                })
                .unwrap_or_default();
        }
        if let Some(result_set) = response.result_set() {
            for row in result_set.rows() {
                let values = row
                    .data()
                    .iter()
                    .map(|datum| {
                        datum
                            .var_char_value()
                            .map(|value| Value::String(value.to_string()))
                            .unwrap_or(Value::Null)
                    })
                    .collect::<Vec<_>>();
                if first_page && is_header_row(&columns, &values) {
                    first_page = false;
                    continue;
                }
                first_page = false;
                if rows.len() >= cap {
                    break;
                }
                rows.push(values);
            }
        }
        next_token = response.next_token().map(str::to_string);
        if rows.len() >= cap || next_token.is_none() {
            break;
        }
    }
    let truncated = rows.len() >= cap && next_token.is_some();
    Ok((columns, rows, truncated))
}

async fn load_metadata(connection: &AthenaConnection) -> Result<Value, String> {
    let sql = "select table_catalog, table_schema, table_name, column_name, data_type, ordinal_position, is_nullable \
               from information_schema.columns \
               where table_schema <> 'information_schema' \
               order by table_catalog, table_schema, table_name, ordinal_position";
    let (columns, rows, _) = run_query(connection, sql, 10_000).await?;
    Ok(metadata_from_rows(&columns, &rows))
}

fn metadata_from_rows(columns: &[String], rows: &[Vec<Value>]) -> Value {
    let mut schemas: BTreeMap<String, BTreeMap<String, ObjectMeta>> = BTreeMap::new();
    for row in rows {
        let catalog =
            field(columns, row, "table_catalog").unwrap_or_else(|| "awsdatacatalog".into());
        let schema = field(columns, row, "table_schema").unwrap_or_else(|| "default".into());
        let table = field(columns, row, "table_name").unwrap_or_default();
        if table.is_empty() {
            continue;
        }
        let schema_name = format!("{catalog}.{schema}");
        let object = schemas
            .entry(schema_name)
            .or_default()
            .entry(table)
            .or_default();
        let ordinal = field(columns, row, "ordinal_position")
            .and_then(|value| value.parse::<i64>().ok())
            .unwrap_or((object.columns.len() + 1) as i64);
        let nullable = field(columns, row, "is_nullable")
            .map(|value| value.eq_ignore_ascii_case("YES") || value.eq_ignore_ascii_case("true"))
            .unwrap_or(true);
        object.columns.push(json!({
            "name": field(columns, row, "column_name").unwrap_or_default(),
            "dataType": field(columns, row, "data_type").unwrap_or_default(),
            "nullable": nullable,
            "ordinal": ordinal
        }));
    }
    json!({
        "schemas": schemas
            .into_iter()
            .map(|(schema, objects)| json!({
                "name": schema,
                "objects": objects
                    .into_iter()
                    .map(|(name, object)| json!({
                        "schema": schema,
                        "name": name,
                        "kind": "table",
                        "columns": object.columns,
                        "indexes": [],
                        "primaryKey": [],
                        "foreignKeys": []
                    }))
                    .collect::<Vec<_>>()
            }))
            .collect::<Vec<_>>()
    })
}

fn is_header_row(columns: &[String], row: &[Value]) -> bool {
    !columns.is_empty()
        && columns.len() == row.len()
        && columns.iter().zip(row.iter()).all(|(column, value)| {
            value
                .as_str()
                .map(|value| value.eq_ignore_ascii_case(column))
                .unwrap_or(false)
        })
}

fn field(columns: &[String], row: &[Value], name: &str) -> Option<String> {
    columns
        .iter()
        .position(|column| column.eq_ignore_ascii_case(name))
        .and_then(|index| row.get(index))
        .and_then(|value| match value {
            Value::Null => None,
            Value::String(value) => Some(value.clone()),
            other => Some(other.to_string()),
        })
}

fn connection(connection_id: &str) -> Result<AthenaConnection, IrodoriConnectorBuffer> {
    let guard = connections().lock().map_err(|_| {
        abi::error(
            "connector.statePoisoned",
            "Connector connection state is poisoned.",
        )
    })?;
    guard.get(connection_id).cloned().ok_or_else(|| {
        abi::error(
            "connector.connectionNotFound",
            format!("no open connection: {connection_id}"),
        )
    })
}

fn request_containers(request: &Value) -> Vec<&Value> {
    [
        Some(request),
        request.get("profile"),
        request.get("options"),
        request.get("auth"),
        request.get("secrets"),
        request
            .get("profile")
            .and_then(|profile| profile.get("options")),
        request
            .get("profile")
            .and_then(|profile| profile.get("auth")),
        request
            .get("profile")
            .and_then(|profile| profile.get("secrets")),
    ]
    .into_iter()
    .flatten()
    .collect()
}

fn option_string(request: &Value, fields: &[&str]) -> Option<String> {
    request_containers(request)
        .into_iter()
        .find_map(|container| {
            fields.iter().find_map(|field| {
                container
                    .get(*field)
                    .map(|value| match value {
                        Value::String(value) => value.clone(),
                        Value::Number(value) => value.to_string(),
                        Value::Bool(value) => value.to_string(),
                        _ => String::new(),
                    })
                    .map(|value| value.trim().to_string())
                    .filter(|value| !value.is_empty())
            })
        })
}

/// The desktop connection form gives this engine two credential boxes labelled
/// "AWS profile / access key" and "Secret / session token", so a profile filled
/// in through the UI arrives with `user`/`password` rather than the explicit
/// option names. `password` is unambiguous — it is the secret access key.
/// `user` is not, so disambiguate it by shape: an access key id is 20 uppercase
/// alphanumerics beginning with `A` (`AKIA…` long-term, `ASIA…` temporary).
/// Anything else is a profile name.
fn looks_like_access_key_id(value: &str) -> bool {
    value.len() == 20
        && value.starts_with('A')
        && value
            .bytes()
            .all(|b| b.is_ascii_uppercase() || b.is_ascii_digit())
}

fn form_access_key_id(request: &Value) -> Option<String> {
    option_string(request, &["user", "username"]).filter(|value| looks_like_access_key_id(value))
}

fn form_profile_name(request: &Value) -> Option<String> {
    option_string(request, &["user", "username"]).filter(|value| !looks_like_access_key_id(value))
}

fn credentials_from_request(request: &Value) -> Option<AwsCredentials> {
    let access_key_id = option_string(
        request,
        &["accessKeyId", "accessKey", "awsAccessKeyId", "awsAccessKey"],
    )
    .or_else(|| form_access_key_id(request))?;
    let secret_access_key = option_string(
        request,
        &[
            "secretAccessKey",
            "secretKey",
            "awsSecretAccessKey",
            "awsSecretKey",
        ],
    )
    .or_else(|| option_string(request, &["password"]))?;
    let session_token = option_string(
        request,
        &["sessionToken", "token", "awsSessionToken", "securityToken"],
    );
    Some(AwsCredentials {
        access_key_id,
        secret_access_key,
        session_token,
    })
}

fn env_credentials() -> Option<AwsCredentials> {
    let access_key_id = std::env::var("AWS_ACCESS_KEY_ID").ok()?;
    let secret_access_key = std::env::var("AWS_SECRET_ACCESS_KEY").ok()?;
    let session_token = std::env::var("AWS_SESSION_TOKEN").ok();
    Some(AwsCredentials {
        access_key_id,
        secret_access_key,
        session_token,
    })
}

fn profile_region(request: &Value) -> Option<String> {
    let profile = option_string(request, &["profile", "awsProfile"])
        .or_else(|| form_profile_name(request))
        .or_else(|| std::env::var("AWS_PROFILE").ok())
        .unwrap_or_else(|| "default".to_string());
    let config = std::env::var("AWS_CONFIG_FILE").ok().or_else(|| {
        std::env::var("HOME")
            .ok()
            .map(|home| format!("{home}/.aws/config"))
    })?;
    read_aws_ini_value(&config, &profile_section_name(&profile), "region")
        .or_else(|| read_aws_ini_value(&config, "default", "region"))
}

fn read_aws_ini_value(path: &str, section: &str, key: &str) -> Option<String> {
    let text = std::fs::read_to_string(path).ok()?;
    let mut current_section = String::new();
    for line in text.lines() {
        let line = line.trim();
        if line.is_empty() || line.starts_with('#') || line.starts_with(';') {
            continue;
        }
        if let Some(section_name) = line
            .strip_prefix('[')
            .and_then(|line| line.strip_suffix(']'))
        {
            current_section = section_name.trim().to_string();
            continue;
        }
        if current_section == section {
            let Some((name, value)) = line.split_once('=') else {
                continue;
            };
            if name.trim() == key {
                let value = value.trim();
                if !value.is_empty() {
                    return Some(value.to_string());
                }
            }
        }
    }
    None
}

fn profile_section_name(profile: &str) -> String {
    if profile == "default" {
        "default".to_string()
    } else {
        format!("profile {profile}")
    }
}

fn normalize_endpoint(value: &str, region: &str) -> String {
    let value = value.trim();
    if value.contains("://") {
        value.trim_end_matches('/').to_string()
    } else if value.is_empty() {
        format!("https://athena.{region}.amazonaws.com")
    } else {
        format!("https://{}", value.trim_end_matches('/'))
    }
}

fn push_sensitive(values: &mut Vec<String>, value: Option<&str>) {
    if let Some(value) = value.map(str::trim).filter(|value| !value.is_empty()) {
        if !values.iter().any(|existing| existing == value) {
            values.push(value.to_string());
        }
    }
}

fn collect_url_auth(url: &str, values: &mut Vec<String>) {
    let Some(after_scheme) = url.split_once("://").map(|(_, rest)| rest) else {
        return;
    };
    let Some(auth) = after_scheme
        .split('/')
        .next()
        .and_then(|host| host.split('@').next())
    else {
        return;
    };
    if auth.contains(':') {
        for part in auth.split(':') {
            push_sensitive(values, Some(part));
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_request_config_from_profile_and_secrets() {
        let request = json!({
            "profile": {
                "region": "us-west-2",
                "workgroup": "analytics",
                "database": "default",
                "outputLocation": "s3://bucket/query-results/",
                "secrets": {
                    "accessKeyId": "key",
                    "secretAccessKey": "secret"
                }
            }
        });
        let config = AthenaConfig::from_request(&request).unwrap();
        assert_eq!(config.region, "us-west-2");
        assert_eq!(config.workgroup, "analytics");
        assert_eq!(config.database.as_deref(), Some("default"));
        assert_eq!(
            config
                .credentials
                .as_ref()
                .map(|creds| creds.access_key_id.as_str()),
            Some("key")
        );
    }

    #[test]
    fn detects_athena_header_row() {
        let columns = vec!["id".to_string(), "name".to_string()];
        let row = vec![json!("id"), json!("name")];
        assert!(is_header_row(&columns, &row));
    }

    #[test]
    fn takes_the_secret_access_key_from_the_password_field() {
        // The connection form labels `user`/`password` "AWS profile / access
        // key" and "Secret / session token", so this is the shape a profile
        // filled in through the UI arrives as.
        let credentials = credentials_from_request(&json!({
            "profile": {
                "user": "AKIAIOSFODNN7EXAMPLE",
                "password": "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY"
            }
        }))
        .expect("form credentials should resolve");
        assert_eq!(credentials.access_key_id, "AKIAIOSFODNN7EXAMPLE");
        assert_eq!(
            credentials.secret_access_key,
            "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY"
        );
    }

    #[test]
    fn a_user_that_is_not_an_access_key_id_is_a_profile_name_not_a_credential() {
        assert!(credentials_from_request(&json!({
            "profile": { "user": "staging", "password": "secret" }
        }))
        .is_none());
        assert_eq!(
            form_profile_name(&json!({ "profile": { "user": "staging" } })).as_deref(),
            Some("staging")
        );
        assert_eq!(
            form_profile_name(&json!({ "profile": { "user": "AKIAIOSFODNN7EXAMPLE" } })),
            None
        );
    }

    #[test]
    fn explicit_credential_options_win_over_the_form_fields() {
        let credentials = credentials_from_request(&json!({
            "profile": {
                "user": "AKIAIOSFODNN7EXAMPLE",
                "password": "from-the-form",
                "options": {
                    "accessKeyId": "AKIAEXPLICITEXPLICIT",
                    "secretAccessKey": "explicit-secret"
                }
            }
        }))
        .expect("explicit credentials should resolve");
        assert_eq!(credentials.access_key_id, "AKIAEXPLICITEXPLICIT");
        assert_eq!(credentials.secret_access_key, "explicit-secret");
    }

    #[test]
    fn recognizes_the_access_key_id_shape() {
        assert!(looks_like_access_key_id("AKIAIOSFODNN7EXAMPLE"));
        assert!(looks_like_access_key_id("ASIAIOSFODNN7EXAMPLE"));
        assert!(!looks_like_access_key_id("default"));
        assert!(!looks_like_access_key_id("akiaiosfodnn7example"));
        assert!(!looks_like_access_key_id("AKIASHORT"));
    }
}
