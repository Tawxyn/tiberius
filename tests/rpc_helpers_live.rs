//! Optional smoke tests for the new RPC helpers against a real SQL Server
//! instance. Gated on `TIBERIUS_TEST_CONNECTION_STRING` — tests are marked
//! `#[ignore]` so a CI that forgets to set the env var sees "skipped"
//! rather than a silent "0 passed".

use futures_util::stream::TryStreamExt;
use std::borrow::Cow;
use std::env;
use tiberius::numeric::Numeric;
use tiberius::{
    Client, ColumnData, Config, CursorOpenOptions, Fetch, ProcedureParameter, QueryItem, TypeInfo,
    VarLenContext, VarLenType,
};
use tokio_util::compat::TokioAsyncWriteCompatExt;

fn int_type() -> TypeInfo {
    TypeInfo::VarLenSized(VarLenContext::new(VarLenType::Intn, 4, None))
}

fn nvarchar_type(len: usize) -> TypeInfo {
    TypeInfo::VarLenSized(VarLenContext::new(
        VarLenType::NVarchar,
        len,
        Some(tiberius::Collation::new(13632521, 52)),
    ))
}

fn nvarchar_max_type() -> TypeInfo {
    nvarchar_type(u16::MAX as usize)
}

fn varbinary_max_type() -> TypeInfo {
    TypeInfo::VarLenSized(VarLenContext::new(
        VarLenType::BigVarBin,
        u16::MAX as usize,
        None,
    ))
}

fn conn_str() -> String {
    env::var("TIBERIUS_TEST_CONNECTION_STRING")
        .expect("TIBERIUS_TEST_CONNECTION_STRING must be set (use `cargo test -- --ignored`)")
}

async fn connect() -> tiberius::Result<Client<tokio_util::compat::Compat<tokio::net::TcpStream>>> {
    let config = Config::from_ado_string(&conn_str())?;
    let tcp = tokio::net::TcpStream::connect(config.get_addr()).await?;
    tcp.set_nodelay(true)?;
    Client::connect(config, tcp.compat_write()).await
}

#[tokio::test]
#[ignore = "requires TIBERIUS_TEST_CONNECTION_STRING; run with --ignored"]
async fn live_prepare_execute_unprepare() -> tiberius::Result<()> {
    let mut client = connect().await?;

    let stmt = client
        .prepare("SELECT @P1 + @P2 AS s", "@P1 int, @P2 int")
        .await?;
    let first_handle = stmt.handle();

    for (a, b, expected) in [(1i32, 2i32, 3i32), (10, 20, 30), (-5, 5, 0)] {
        let row = stmt
            .query(&mut client, &[&a, &b])
            .await?
            .into_row()
            .await?
            .unwrap();
        assert_eq!(row.get::<i32, _>(0), Some(expected));
    }

    // Handle must be stable across executes — catches server-side slot-reuse bugs.
    assert_eq!(stmt.handle(), first_handle);

    stmt.unprepare(&mut client).await?;
    Ok(())
}

#[tokio::test]
#[ignore = "requires TIBERIUS_TEST_CONNECTION_STRING; run with --ignored"]
async fn live_prep_exec_returns_handle_and_rows() -> tiberius::Result<()> {
    let mut client = connect().await?;

    let (stmt, results) = client
        .prep_exec("SELECT @P1 AS v", "@P1 int", &[&42i32])
        .await?;
    let first_handle = stmt.handle();
    assert_eq!(results.len(), 1);
    assert_eq!(results[0].len(), 1);
    assert_eq!(results[0][0].get::<i32, _>(0), Some(42));

    // Reuse the handle.
    let row = stmt
        .query(&mut client, &[&99i32])
        .await?
        .into_row()
        .await?
        .unwrap();
    assert_eq!(row.get::<i32, _>(0), Some(99));
    assert_eq!(stmt.handle(), first_handle);

    stmt.unprepare(&mut client).await?;
    Ok(())
}

#[tokio::test]
#[ignore = "requires TIBERIUS_TEST_CONNECTION_STRING; run with --ignored"]
async fn live_open_fetch_close_cursor() -> tiberius::Result<()> {
    let mut client = connect().await?;

    let cursor = client
        .open_cursor(
            "SELECT 1 AS v UNION ALL SELECT 2 AS v UNION ALL SELECT 3 AS v",
            CursorOpenOptions::default(),
            "",
            &[],
        )
        .await?;

    let mut all = Vec::new();
    loop {
        let mut stream = cursor.fetch(&mut client, Fetch::Next { count: 10 }).await?;
        let mut got_any = false;
        while let Some(item) = stream.try_next().await? {
            if let QueryItem::Row(row) = item {
                got_any = true;
                all.push(row.get::<i32, _>(0).unwrap());
            }
        }
        if !got_any {
            break;
        }
    }
    assert_eq!(all, vec![1, 2, 3]);

    cursor.close(&mut client).await?;
    Ok(())
}

#[tokio::test]
#[ignore = "requires TIBERIUS_TEST_CONNECTION_STRING; run with --ignored"]
async fn live_prepared_across_table() -> tiberius::Result<()> {
    let mut client = connect().await?;

    // Use a temp table to exercise something more lifelike.
    client
        .simple_query(
            "IF OBJECT_ID('tempdb..##tiberius_rpc_helpers_live', 'U') IS NOT NULL \
             DROP TABLE ##tiberius_rpc_helpers_live; \
             CREATE TABLE ##tiberius_rpc_helpers_live (id int, name nvarchar(50))",
        )
        .await?
        .into_results()
        .await?;

    let insert = client
        .prepare(
            "INSERT INTO ##tiberius_rpc_helpers_live (id, name) VALUES (@P1, @P2)",
            "@P1 int, @P2 nvarchar(50)",
        )
        .await?;
    for (id, name) in [(1, "alpha"), (2, "beta"), (3, "gamma")] {
        insert.execute(&mut client, &[&id, &name]).await?;
    }
    insert.unprepare(&mut client).await?;

    let select = client
        .prepare(
            "SELECT id, name FROM ##tiberius_rpc_helpers_live WHERE id >= @P1 ORDER BY id",
            "@P1 int",
        )
        .await?;
    let rows = select
        .query(&mut client, &[&2i32])
        .await?
        .into_first_result()
        .await?;
    assert_eq!(rows.len(), 2);
    assert_eq!(rows[0].get::<i32, _>(0), Some(2));
    assert_eq!(rows[0].get::<&str, _>(1), Some("beta"));
    assert_eq!(rows[1].get::<i32, _>(0), Some(3));
    assert_eq!(rows[1].get::<&str, _>(1), Some("gamma"));
    select.unprepare(&mut client).await?;

    client
        .simple_query("DROP TABLE ##tiberius_rpc_helpers_live")
        .await?
        .into_results()
        .await?;
    Ok(())
}

#[tokio::test]
#[ignore = "requires TIBERIUS_TEST_CONNECTION_STRING; run with --ignored"]
async fn live_call_procedure_with_output_and_return_status() -> tiberius::Result<()> {
    let mut client = connect().await?;

    client
        .simple_query(
            "IF OBJECT_ID('tempdb..##tiberius_call_procedure_test', 'P') IS NOT NULL \
             DROP PROCEDURE ##tiberius_call_procedure_test",
        )
        .await?
        .into_results()
        .await?;
    client
        .simple_query(
            "CREATE PROCEDURE ##tiberius_call_procedure_test \
                 @in INT, @out INT OUTPUT, @io INT OUTPUT \
             AS BEGIN \
                 PRINT 'tiberius_call_procedure_test: running'; \
                 SET @out = @in * 2; \
                 SET @io = @io + 1; \
                 SELECT @in AS v; \
                 RETURN @in; \
             END",
        )
        .await?
        .into_results()
        .await?;

    let result = client
        .call_procedure(
            "##tiberius_call_procedure_test",
            vec![
                ProcedureParameter::input(int_type(), ColumnData::I32(Some(21))).named("@in"),
                ProcedureParameter::output(int_type(), ColumnData::I32(Some(0))).named("@out"),
                ProcedureParameter::input_output(int_type(), ColumnData::I32(Some(9))).named("@io"),
            ],
        )
        .await?;

    assert_eq!(result.result_sets.len(), 1);
    assert_eq!(result.result_sets[0].rows.len(), 1);
    assert_eq!(result.result_sets[0].rows[0].get::<i32, _>(0), Some(21));
    assert_eq!(result.return_status, Some(21));
    assert!(result.messages.iter().any(|m| m
        .message()
        .contains("tiberius_call_procedure_test: running")));

    let out = result
        .output_values
        .iter()
        .find(|o| o.matches_name("@out"))
        .expect("expected @out output value");
    assert_eq!(out.get::<i32>()?, Some(42));

    let io = result
        .output_values
        .iter()
        .find(|o| o.matches_name("@io"))
        .expect("expected @io output value");
    assert_eq!(io.get::<i32>()?, Some(10));

    // A negative RETURN status must survive the RPC round trip as a signed
    // value, and the connection must be reusable for another call.
    let result2 = client
        .call_procedure(
            "##tiberius_call_procedure_test",
            vec![
                ProcedureParameter::input(int_type(), ColumnData::I32(Some(-3))).named("@in"),
                ProcedureParameter::output(int_type(), ColumnData::I32(Some(0))).named("@out"),
                ProcedureParameter::input_output(int_type(), ColumnData::I32(Some(0))).named("@io"),
            ],
        )
        .await?;
    assert_eq!(result2.return_status, Some(-3));

    client
        .simple_query("DROP PROCEDURE ##tiberius_call_procedure_test")
        .await?
        .into_results()
        .await?;
    Ok(())
}

#[tokio::test]
#[ignore = "requires TIBERIUS_TEST_CONNECTION_STRING; run with --ignored"]
async fn live_call_procedure_surfaces_raiserror() -> tiberius::Result<()> {
    let mut client = connect().await?;

    client
        .simple_query(
            "IF OBJECT_ID('tempdb..##tiberius_call_procedure_error', 'P') IS NOT NULL \
             DROP PROCEDURE ##tiberius_call_procedure_error",
        )
        .await?
        .into_results()
        .await?;
    client
        .simple_query(
            "CREATE PROCEDURE ##tiberius_call_procedure_error AS \
             BEGIN RAISERROR('tiberius_call_procedure_error: boom', 16, 1); END",
        )
        .await?
        .into_results()
        .await?;

    let err = client
        .call_procedure("##tiberius_call_procedure_error", Vec::new())
        .await
        .unwrap_err();
    match err {
        tiberius::error::Error::Server(e) => {
            assert!(e.message().contains("tiberius_call_procedure_error: boom"))
        }
        other => panic!("expected Server error, got {:?}", other),
    }

    // The connection must still be usable after a server-side error.
    client
        .simple_query("SELECT 1")
        .await?
        .into_results()
        .await?;

    client
        .simple_query("DROP PROCEDURE ##tiberius_call_procedure_error")
        .await?
        .into_results()
        .await?;
    Ok(())
}

#[tokio::test]
#[ignore = "requires TIBERIUS_TEST_CONNECTION_STRING; run with --ignored"]
async fn live_call_procedure_cancellation_leaves_connection_reusable() -> tiberius::Result<()> {
    let mut client = connect().await?;

    let token = client.cancellation_token();
    let canceller = tokio::spawn(async move {
        tokio::time::sleep(std::time::Duration::from_millis(200)).await;
        token.cancel();
    });

    let start = std::time::Instant::now();
    let result = client
        .call_procedure(
            "sp_executesql",
            vec![ProcedureParameter::input(
                nvarchar_type(0xffff),
                ColumnData::String(Some(Cow::Borrowed("WAITFOR DELAY '00:00:30'"))),
            )],
        )
        .await;
    let elapsed = start.elapsed();
    canceller.await.ok();

    assert!(
        elapsed < std::time::Duration::from_secs(5),
        "cancellation did not interrupt call_procedure: took {elapsed:?}"
    );
    assert!(
        matches!(&result, Err(tiberius::error::Error::Canceled)),
        "expected Error::Canceled, got {result:?}"
    );

    // Connection is still reusable after the cancel drain.
    let rows = client
        .simple_query("SELECT 42")
        .await?
        .into_row()
        .await?
        .unwrap();
    assert_eq!(rows.get::<i32, _>(0), Some(42));
    Ok(())
}

/// Creates a procedure echoing `@in` back through `@out OUTPUT`, replacing
/// any existing one of that name.
async fn create_echo_procedure(
    client: &mut Client<tokio_util::compat::Compat<tokio::net::TcpStream>>,
    proc_name: &str,
    sql_type: &str,
) -> tiberius::Result<()> {
    client
        .simple_query(format!(
            "IF OBJECT_ID('tempdb..{proc_name}', 'P') IS NOT NULL DROP PROCEDURE {proc_name}"
        ))
        .await?
        .into_results()
        .await?;
    client
        .simple_query(format!(
            "CREATE PROCEDURE {proc_name} @in {sql_type}, @out {sql_type} OUTPUT \
             AS BEGIN SET @out = @in; END"
        ))
        .await?
        .into_results()
        .await?;
    Ok(())
}

#[tokio::test]
#[ignore = "requires TIBERIUS_TEST_CONNECTION_STRING; run with --ignored"]
async fn live_call_procedure_echoes_strings_bounded_and_max() -> tiberius::Result<()> {
    let mut client = connect().await?;
    create_echo_procedure(&mut client, "##tiberius_echo_nvarchar", "nvarchar(max)").await?;

    // Single-packet sized; multi-packet is covered by
    // `live_call_procedure_multi_packet_clob_and_blob`.
    let long_value = "tiberius-".repeat(100);

    let result = client
        .call_procedure(
            "##tiberius_echo_nvarchar",
            vec![
                ProcedureParameter::input(
                    nvarchar_type(50),
                    ColumnData::String(Some(Cow::Borrowed("hello"))),
                )
                .named("@in"),
                ProcedureParameter::output(nvarchar_type(0xffff), ColumnData::String(None))
                    .named("@out"),
            ],
        )
        .await?;
    let out = result
        .output_values
        .iter()
        .find(|o| o.matches_name("@out"))
        .unwrap();
    assert_eq!(out.get::<&str>()?, Some("hello"));

    let result = client
        .call_procedure(
            "##tiberius_echo_nvarchar",
            vec![
                ProcedureParameter::input(
                    nvarchar_type(0xffff),
                    ColumnData::String(Some(Cow::Owned(long_value.clone()))),
                )
                .named("@in"),
                ProcedureParameter::output(nvarchar_type(0xffff), ColumnData::String(None))
                    .named("@out"),
            ],
        )
        .await?;
    let out = result
        .output_values
        .iter()
        .find(|o| o.matches_name("@out"))
        .unwrap();
    assert_eq!(out.get::<&str>()?, Some(long_value.as_str()));

    client
        .simple_query("DROP PROCEDURE ##tiberius_echo_nvarchar")
        .await?
        .into_results()
        .await?;
    Ok(())
}

#[tokio::test]
#[ignore = "requires TIBERIUS_TEST_CONNECTION_STRING; run with --ignored"]
async fn live_call_procedure_echoes_binary_bounded_and_max() -> tiberius::Result<()> {
    let mut client = connect().await?;
    create_echo_procedure(&mut client, "##tiberius_echo_varbinary", "varbinary(max)").await?;

    let bounded_ty = TypeInfo::VarLenSized(VarLenContext::new(VarLenType::BigVarBin, 50, None));
    let max_ty = TypeInfo::VarLenSized(VarLenContext::new(VarLenType::BigVarBin, 0xffff, None));
    let long_value: Vec<u8> = (0..1500u32).map(|i| (i % 256) as u8).collect();

    let result = client
        .call_procedure(
            "##tiberius_echo_varbinary",
            vec![
                ProcedureParameter::input(
                    bounded_ty,
                    ColumnData::Binary(Some(Cow::Borrowed(&[1u8, 2, 3][..]))),
                )
                .named("@in"),
                ProcedureParameter::output(max_ty.clone(), ColumnData::Binary(None)).named("@out"),
            ],
        )
        .await?;
    let out = result
        .output_values
        .iter()
        .find(|o| o.matches_name("@out"))
        .unwrap();
    assert_eq!(out.get::<&[u8]>()?, Some(&[1u8, 2, 3][..]));

    let result = client
        .call_procedure(
            "##tiberius_echo_varbinary",
            vec![
                ProcedureParameter::input(
                    max_ty.clone(),
                    ColumnData::Binary(Some(Cow::Owned(long_value.clone()))),
                )
                .named("@in"),
                ProcedureParameter::output(max_ty, ColumnData::Binary(None)).named("@out"),
            ],
        )
        .await?;
    let out = result
        .output_values
        .iter()
        .find(|o| o.matches_name("@out"))
        .unwrap();
    assert_eq!(out.get::<&[u8]>()?, Some(long_value.as_slice()));

    client
        .simple_query("DROP PROCEDURE ##tiberius_echo_varbinary")
        .await?
        .into_results()
        .await?;
    Ok(())
}

#[tokio::test]
#[ignore = "requires TIBERIUS_TEST_CONNECTION_STRING; run with --ignored"]
async fn live_call_procedure_echoes_null_output() -> tiberius::Result<()> {
    let mut client = connect().await?;
    create_echo_procedure(&mut client, "##tiberius_echo_null", "int").await?;

    let result = client
        .call_procedure(
            "##tiberius_echo_null",
            vec![
                ProcedureParameter::input(int_type(), ColumnData::I32(None)).named("@in"),
                ProcedureParameter::output(int_type(), ColumnData::I32(Some(0))).named("@out"),
            ],
        )
        .await?;
    let out = result
        .output_values
        .iter()
        .find(|o| o.matches_name("@out"))
        .unwrap();
    assert_eq!(out.get::<i32>()?, None);

    client
        .simple_query("DROP PROCEDURE ##tiberius_echo_null")
        .await?
        .into_results()
        .await?;
    Ok(())
}

#[tokio::test]
#[ignore = "requires TIBERIUS_TEST_CONNECTION_STRING; run with --ignored"]
async fn live_call_procedure_numeric_precision_scale() -> tiberius::Result<()> {
    let mut client = connect().await?;
    create_echo_procedure(&mut client, "##tiberius_echo_numeric", "numeric(18,2)").await?;

    let ty = TypeInfo::VarLenSizedPrecision {
        ty: VarLenType::Numericn,
        size: 17,
        precision: 18,
        scale: 2,
    };
    let result = client
        .call_procedure(
            "##tiberius_echo_numeric",
            vec![
                ProcedureParameter::input(
                    ty.clone(),
                    ColumnData::Numeric(Some(Numeric::new_with_scale(123_456, 2))),
                )
                .named("@in"),
                ProcedureParameter::output(ty, ColumnData::Numeric(None)).named("@out"),
            ],
        )
        .await?;
    let out = result
        .output_values
        .iter()
        .find(|o| o.matches_name("@out"))
        .unwrap();
    match out.raw() {
        ColumnData::Numeric(Some(n)) => {
            assert_eq!(*n, Numeric::new_with_scale(123_456, 2));
        }
        other => panic!("expected Numeric, got {:?}", other),
    }

    client
        .simple_query("DROP PROCEDURE ##tiberius_echo_numeric")
        .await?
        .into_results()
        .await?;
    Ok(())
}

#[tokio::test]
#[ignore = "requires TIBERIUS_TEST_CONNECTION_STRING; run with --ignored"]
async fn live_call_procedure_output_ordinal_mapping() -> tiberius::Result<()> {
    let mut client = connect().await?;

    client
        .simple_query(
            "IF OBJECT_ID('tempdb..##tiberius_ordinal_proc', 'P') IS NOT NULL \
             DROP PROCEDURE ##tiberius_ordinal_proc",
        )
        .await?
        .into_results()
        .await?;
    client
        .simple_query(
            "CREATE PROCEDURE ##tiberius_ordinal_proc \
                 @first INT OUTPUT, @second NVARCHAR(50) OUTPUT, @third INT OUTPUT \
             AS BEGIN SET @first = 1; SET @second = N'second'; SET @third = 3; END",
        )
        .await?
        .into_results()
        .await?;

    let result = client
        .call_procedure(
            "##tiberius_ordinal_proc",
            vec![
                ProcedureParameter::output(int_type(), ColumnData::I32(Some(0))).named("@first"),
                ProcedureParameter::output(nvarchar_type(50), ColumnData::String(None))
                    .named("@second"),
                ProcedureParameter::output(int_type(), ColumnData::I32(Some(0))).named("@third"),
            ],
        )
        .await?;

    assert_eq!(result.output_values.len(), 3);
    // Strictly increasing rather than a literal base: the starting value is
    // not a documented contract.
    assert_eq!(result.output_values[0].name(), "@first");
    assert_eq!(result.output_values[1].name(), "@second");
    assert_eq!(result.output_values[2].name(), "@third");
    assert!(
        result.output_values[0].ordinal() < result.output_values[1].ordinal()
            && result.output_values[1].ordinal() < result.output_values[2].ordinal(),
        "expected strictly increasing ordinals, got {:?}",
        result
            .output_values
            .iter()
            .map(|o| o.ordinal())
            .collect::<Vec<_>>()
    );

    client
        .simple_query("DROP PROCEDURE ##tiberius_ordinal_proc")
        .await?
        .into_results()
        .await?;
    Ok(())
}

#[tokio::test]
#[ignore = "requires TIBERIUS_TEST_CONNECTION_STRING; run with --ignored"]
async fn live_call_procedure_multiple_results() -> tiberius::Result<()> {
    let mut client = connect().await?;

    client
        .simple_query(
            "IF OBJECT_ID('tempdb..##tiberius_multi_result_proc', 'P') IS NOT NULL \
             DROP PROCEDURE ##tiberius_multi_result_proc",
        )
        .await?
        .into_results()
        .await?;
    client
        .simple_query(
            "CREATE PROCEDURE ##tiberius_multi_result_proc AS BEGIN \
                 SELECT 1 AS v UNION ALL SELECT 2 UNION ALL SELECT 3; \
                 SELECT 4 AS v UNION ALL SELECT 5; \
             END",
        )
        .await?
        .into_results()
        .await?;

    let result = client
        .call_procedure("##tiberius_multi_result_proc", Vec::new())
        .await?;

    assert_eq!(result.result_sets.len(), 2);
    let first: Vec<i32> = result.result_sets[0]
        .rows
        .iter()
        .map(|r| r.get::<i32, _>(0).unwrap())
        .collect();
    assert_eq!(first, vec![1, 2, 3]);
    let second: Vec<i32> = result.result_sets[1]
        .rows
        .iter()
        .map(|r| r.get::<i32, _>(0).unwrap())
        .collect();
    assert_eq!(second, vec![4, 5]);

    client
        .simple_query("DROP PROCEDURE ##tiberius_multi_result_proc")
        .await?
        .into_results()
        .await?;
    Ok(())
}

#[tokio::test]
#[ignore = "requires TIBERIUS_TEST_CONNECTION_STRING; run with --ignored"]
async fn live_call_procedure_positional_binding() -> tiberius::Result<()> {
    let mut client = connect().await?;

    client
        .simple_query(
            "IF OBJECT_ID('tempdb..##tiberius_positional_proc', 'P') IS NOT NULL \
             DROP PROCEDURE ##tiberius_positional_proc",
        )
        .await?
        .into_results()
        .await?;
    client
        .simple_query(
            "CREATE PROCEDURE ##tiberius_positional_proc \
                 @a INT, @b INT OUTPUT, @c INT OUTPUT \
             AS BEGIN \
                 SET @b = @a * 2; \
                 SET @c = @c + 100; \
                 SELECT @a AS v; \
                 RETURN @a; \
             END",
        )
        .await?
        .into_results()
        .await?;

    // No parameter carries a name, so the server binds purely by descriptor
    // order. Mixes all three directions to prove order is preserved across
    // them rather than only across a uniform set.
    let result = client
        .call_procedure(
            "##tiberius_positional_proc",
            vec![
                ProcedureParameter::input(int_type(), ColumnData::I32(Some(21))),
                ProcedureParameter::output(int_type(), ColumnData::I32(None)),
                ProcedureParameter::input_output(int_type(), ColumnData::I32(Some(5))),
            ],
        )
        .await?;

    assert_eq!(result.return_status, Some(21));
    assert_eq!(result.result_sets.len(), 1);
    assert_eq!(result.result_sets[0].rows[0].get::<i32, _>(0), Some(21));

    // Only the two byref parameters come back, in descriptor order.
    assert_eq!(result.output_values.len(), 2);
    assert_eq!(result.output_values[0].get::<i32>()?, Some(42)); // @b = @a * 2
    assert_eq!(result.output_values[1].get::<i32>()?, Some(105)); // @c = 5 + 100

    // Positional outputs carry no name, so consumers must address them by
    // position; `matches_name` must not match an empty name.
    for out in &result.output_values {
        assert_eq!(out.name(), "");
        assert!(!out.matches_name("@b"));
    }

    // Ordinals track the descriptor position of each parameter in the
    // procedure signature (@a, @b, @c), so they stay strictly increasing.
    assert!(
        result.output_values[0].ordinal() < result.output_values[1].ordinal(),
        "expected strictly increasing ordinals, got {:?}",
        result
            .output_values
            .iter()
            .map(|o| o.ordinal())
            .collect::<Vec<_>>()
    );

    // The connection is reusable for a further positional call.
    let again = client
        .call_procedure(
            "##tiberius_positional_proc",
            vec![
                ProcedureParameter::input(int_type(), ColumnData::I32(Some(-7))),
                ProcedureParameter::output(int_type(), ColumnData::I32(None)),
                ProcedureParameter::input_output(int_type(), ColumnData::I32(Some(0))),
            ],
        )
        .await?;
    assert_eq!(again.return_status, Some(-7));
    assert_eq!(again.output_values[0].get::<i32>()?, Some(-14));

    client
        .simple_query("DROP PROCEDURE ##tiberius_positional_proc")
        .await?
        .into_results()
        .await?;
    Ok(())
}

#[tokio::test]
#[ignore = "requires TIBERIUS_TEST_CONNECTION_STRING; run with --ignored"]
async fn live_call_procedure_multi_packet_clob_and_blob() -> tiberius::Result<()> {
    let mut client = connect().await?;
    create_echo_procedure(&mut client, "##tiberius_echo_clob", "nvarchar(max)").await?;
    create_echo_procedure(&mut client, "##tiberius_echo_blob", "varbinary(max)").await?;

    // Well past a single 4 KiB TDS packet in both directions.
    let clob = "tiberius-clob-".repeat(4_000); // 56_000 chars / 112_000 bytes
    assert!(clob.len() * 2 > 4096 * 8);

    let result = client
        .call_procedure(
            "##tiberius_echo_clob",
            vec![
                ProcedureParameter::input(
                    nvarchar_max_type(),
                    ColumnData::String(Some(Cow::Owned(clob.clone()))),
                )
                .named("@in"),
                ProcedureParameter::output(nvarchar_max_type(), ColumnData::String(None))
                    .named("@out"),
            ],
        )
        .await?;
    let out = result
        .output_values
        .iter()
        .find(|o| o.matches_name("@out"))
        .unwrap();
    assert_eq!(out.get::<&str>()?, Some(clob.as_str()));

    let blob: Vec<u8> = (0..100_000u32).map(|i| (i % 251) as u8).collect();
    let result = client
        .call_procedure(
            "##tiberius_echo_blob",
            vec![
                ProcedureParameter::input(
                    varbinary_max_type(),
                    ColumnData::Binary(Some(Cow::Owned(blob.clone()))),
                )
                .named("@in"),
                ProcedureParameter::output(varbinary_max_type(), ColumnData::Binary(None))
                    .named("@out"),
            ],
        )
        .await?;
    let out = result
        .output_values
        .iter()
        .find(|o| o.matches_name("@out"))
        .unwrap();
    assert_eq!(out.get::<&[u8]>()?, Some(blob.as_slice()));

    // Connection still usable after bulk transfers.
    let row = client
        .simple_query("SELECT 42")
        .await?
        .into_row()
        .await?
        .unwrap();
    assert_eq!(row.get::<i32, _>(0), Some(42));

    client
        .simple_query("DROP PROCEDURE ##tiberius_echo_clob; DROP PROCEDURE ##tiberius_echo_blob")
        .await?
        .into_results()
        .await?;
    Ok(())
}

type LiveClient = Client<tokio_util::compat::Compat<tokio::net::TcpStream>>;

async fn batch_error(client: &mut LiveClient, sql: String) -> Option<tiberius::error::Error> {
    match client.simple_query(sql).await {
        Ok(stream) => stream.into_results().await.err(),
        Err(error) => Some(error),
    }
}

async fn assert_prepared_handle_released(client: &mut LiveClient, handle: i32) {
    let error = batch_error(client, format!("EXEC sp_execute {handle}, 0")).await;
    // 8179: Could not find prepared statement with handle.
    assert_eq!(
        error.and_then(|error| error.code()),
        Some(8179),
        "prepared handle {handle} is still allocated"
    );
}

async fn count_rows(client: &mut LiveClient, table: &str) -> tiberius::Result<i32> {
    let row = client
        .simple_query(format!("SELECT COUNT(*) FROM {table}"))
        .await?
        .into_row()
        .await?
        .unwrap();
    Ok(row.get::<i32, _>(0).unwrap())
}

/// Prepares `sql` with one int parameter, executing it once with `first`.
async fn prepare_with_first_row(
    client: &mut LiveClient,
    sql: &'static str,
    first: &'static i32,
) -> tiberius::PreparedStatement {
    let (statement, result, error) = client.prep_exec_until_error(sql, "@P1 int", &[first]).await;
    assert!(error.is_none(), "unexpected error: {error:?}");
    assert_eq!(result.total(), 1);
    statement.expect("sp_prepexec assigned a handle")
}

#[tokio::test]
#[ignore = "requires TIBERIUS_TEST_CONNECTION_STRING; run with --ignored"]
async fn live_execute_and_unprepare_releases_the_handle() -> tiberius::Result<()> {
    let mut client = connect().await?;
    client
        .simple_query("CREATE TABLE #release (id int PRIMARY KEY)")
        .await?
        .into_results()
        .await?;
    let statement =
        prepare_with_first_row(&mut client, "INSERT INTO #release VALUES (@P1)", &1).await;
    let handle = statement.handle().as_i32();

    let (result, error) = statement.execute_and_unprepare(&mut client, &[&2i32]).await;

    assert!(error.is_none(), "unexpected error: {error:?}");
    assert_eq!(result.total(), 1);
    assert_prepared_handle_released(&mut client, handle).await;
    assert_eq!(count_rows(&mut client, "#release").await?, 2);
    Ok(())
}

#[tokio::test]
#[ignore = "requires TIBERIUS_TEST_CONNECTION_STRING; run with --ignored"]
async fn live_execute_and_unprepare_releases_the_handle_after_an_error() -> tiberius::Result<()> {
    let mut client = connect().await?;
    client
        .simple_query("CREATE TABLE #release_error (id int PRIMARY KEY)")
        .await?
        .into_results()
        .await?;
    let statement =
        prepare_with_first_row(&mut client, "INSERT INTO #release_error VALUES (@P1)", &1).await;
    let handle = statement.handle().as_i32();

    let (result, error) = statement.execute_and_unprepare(&mut client, &[&1i32]).await;

    assert_eq!(result.total(), 0);
    assert_eq!(error.and_then(|error| error.code()), Some(2627));
    assert_prepared_handle_released(&mut client, handle).await;
    assert_eq!(count_rows(&mut client, "#release_error").await?, 1);
    Ok(())
}

#[tokio::test]
#[ignore = "requires TIBERIUS_TEST_CONNECTION_STRING; run with --ignored"]
async fn live_execute_and_unprepare_releases_the_handle_after_a_cancel() -> tiberius::Result<()> {
    let mut client = connect().await?;
    client
        .simple_query("CREATE TABLE #release_cancel (id int PRIMARY KEY)")
        .await?
        .into_results()
        .await?;
    let statement = prepare_with_first_row(
        &mut client,
        "IF @P1 = 1 WAITFOR DELAY '00:00:30'; INSERT INTO #release_cancel VALUES (@P1)",
        &0,
    )
    .await;
    let handle = statement.handle().as_i32();

    let token = client.cancellation_token();
    let canceller = tokio::spawn(async move {
        tokio::time::sleep(std::time::Duration::from_millis(200)).await;
        token.cancel();
    });
    let start = std::time::Instant::now();
    let (_result, error) = statement.execute_and_unprepare(&mut client, &[&1i32]).await;
    let elapsed = start.elapsed();
    canceller.await.ok();

    assert!(
        elapsed < std::time::Duration::from_secs(5),
        "cancellation did not interrupt the execution: took {elapsed:?}"
    );
    assert!(
        matches!(&error, Some(tiberius::error::Error::Canceled)),
        "expected Error::Canceled, got {error:?}"
    );
    assert_prepared_handle_released(&mut client, handle).await;
    assert_eq!(count_rows(&mut client, "#release_cancel").await?, 1);
    Ok(())
}

#[tokio::test]
#[ignore = "requires TIBERIUS_TEST_CONNECTION_STRING; run with --ignored"]
async fn live_prepared_cursor_unprepare_closes_an_open_cursor() -> tiberius::Result<()> {
    let mut client = connect().await?;
    let cursor = client
        .cursor_prep_exec(
            "SELECT 1 AS v UNION ALL SELECT 2 AS v UNION ALL SELECT 3 AS v",
            CursorOpenOptions::default(),
            "",
            &[],
        )
        .await?
        .into_cursor()
        .expect("expected a server cursor");
    let cursor_handle = cursor.cursor_handle().as_i32();

    cursor.unprepare(&mut client).await?;

    assert!(
        batch_error(&mut client, format!("EXEC sp_cursorfetch {cursor_handle}"))
            .await
            .is_some(),
        "cursor {cursor_handle} is still open"
    );
    let row = client
        .simple_query("SELECT 42")
        .await?
        .into_row()
        .await?
        .unwrap();
    assert_eq!(row.get::<i32, _>(0), Some(42));
    Ok(())
}
