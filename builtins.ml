(*
 * Built-in operator definitions
 * and common utilities for readability
 *)

open Utils
open Printf

let init_table_size = 10000

(*
 * dump : ?show_reset:bool -> out_channel -> operator
 *
 * Dump all fields of all tuples to the given output channel
 * Note that dump is terminal in that it does not take a continuation operator as argument
 *)
let dump ?(show_reset=false) outc =
    {
        next = (fun p -> dump_tuple outc p) ;
        reset = (fun p ->
            if show_reset
            then (dump_tuple outc p ; fprintf outc "[reset]\n")
        ) ;
    }

(*
 * dump_csv : out_channel -> operator
 *
 * Tries to dump a nice csv-style output
 * Assumes all tuples have the same fields in the same order...
 *)
let dump_csv ?(static_field:(string*string)option = None) ?(header=true) outc =
    let first = ref header in
    {
        next = (fun p ->
            if !first
            then (
                (match static_field with
                    | Some (k,_) -> fprintf outc "%s," k
                    | None -> () );
                Tuple.iter (fun k _ -> fprintf outc "%s," k) p;
                fprintf outc "\n";
                first := false
            ) ;
            (match static_field with
                | Some (_,v) -> fprintf outc "%s," v
                | None -> () );
            Tuple.iter (fun _ v -> fprintf outc "%s," (string_of_op_result v)) p;
            fprintf outc "\n"
        );
        reset = fun _ -> ();
    }

(*
 * dump_walts_csv : out_channel -> operator
 *
 * Dumps csv in Walt's canonical csv format: src_ip, dst_ip, src_l4_port, dst_l4_port, packet_count, byte_count, epoch_id
 * Unused fields are zeroed, map packet length to src_l4_port for ssh brute force
 *)
let dump_walts_csv file_name =
    let outc = ref stdout in
    let first = ref true in
    {
        next = (fun p ->
            if !first then (
                outc := open_out file_name ;
                first := false
            ) ;
            fprintf !outc "%s,%s,%s,%s,%s,%s,%s\n"
                (Tuple.find "src_ip" p |> string_of_op_result)
                (Tuple.find "dst_ip" p |> string_of_op_result)
                (Tuple.find "src_l4_port" p |> string_of_op_result)
                (Tuple.find "dst_l4_port" p |> string_of_op_result)
                (Tuple.find "packet_count" p |> string_of_op_result)
                (Tuple.find "byte_count" p |> string_of_op_result)
                (Tuple.find "epoch_id" p |> string_of_op_result)
        );
        reset = fun _ -> ();
    }

(*
 * Reads an intermediate result CSV in Walt's canonical format
 * Injects epoch ids and incomming tuple counts into reset call
 *)
let get_ip_or_zero s =
    match s with 
        | "0" -> Int 0
        | s -> IPv4 (Ipaddr.V4.of_string_exn s)

(* TODO: read files in RR order... otherwise the whole file gets cached in joins *)
let read_walts_csv ?(epoch_id_key="eid") file_names ops =
    let in_chs_eids_tuples = List.map (fun file_name -> (Scanf.Scanning.open_in file_name, ref 0, ref 0)) file_names in
    let running = ref (List.length ops) in
    while !running > 0 do
        List.iter2 (fun (in_ch, eid, tuples) op ->
            if !eid >= 0 then
            try Scanf.bscanf in_ch "%[0-9.],%[0-9.],%d,%d,%d,%d,%d\n"
                    (fun src_ip dst_ip src_l4_port dst_l4_port packet_count byte_count epoch_id ->
                        let p = Tuple.empty
                            |> Tuple.add "ipv4.src" (get_ip_or_zero src_ip)
                            |> Tuple.add "ipv4.dst" (get_ip_or_zero dst_ip)
                            |> Tuple.add "l4.sport" (Int src_l4_port)
                            |> Tuple.add "l4.dport" (Int dst_l4_port)
                            |> Tuple.add "packet_count" (Int packet_count)
                            |> Tuple.add "byte_count" (Int byte_count)
                            |> Tuple.add epoch_id_key (Int epoch_id)
                        in
                            incr tuples ;
                            if epoch_id > !eid
                            then (
                                while epoch_id > !eid do
                                    op.reset (Tuple.add "tuples" (Int !tuples) (Tuple.singleton epoch_id_key (Int !eid))) ;
                                    tuples := 0 ;
                                    incr eid
                                done
                            ) ;
                            op.next (Tuple.add "tuples" (Int !tuples) p)
                    )
            with
                | Scanf.Scan_failure s -> (printf "Failed to scan: %s\n" s ; raise (Failure "Scan failure"))
                | End_of_file -> (
                    op.reset (Tuple.add "tuples" (Int !tuples) (Tuple.singleton epoch_id_key (Int (!eid + 1)))) ;
                    running := !running - 1 ;
                    eid := -1
                )
        ) in_chs_eids_tuples ops
    done ;
    printf "Done.\n"

(*
 * meta_meter : string -> out_channel -> operator
 *
 * Write the number of tuples passing through this operator each epoch
 * to the out_channel
 *)
let meta_meter ?(static_field:string option = None) name outc op =
    let e = ref 0 in
    let c = ref 0 in
    {
        next = (fun p -> incr c ; op.next p);
        reset = (fun p ->
            fprintf outc "%d,%s,%d,%s\n" !e name !c
                (match static_field with
                    | Some v -> v
                    | None -> "" );
            c := 0;
            incr e;
            op.reset p
        );
    }

(*
 * epoch : float -> string -> operator -> operator
 *
 * Passes tuples through to op
 * Resets op every w seconds
 * Adds epoch id to tuple under key_out
 *)
let epoch w key_out op =
    let e = ref 0.0 in
    let eid = ref 0 in
    {
        next = (fun p ->
            let time = float_of_op_result (Tuple.find "time" p) in
            if !e = 0.0
            then e := time +. w
            else if time >= !e
            then (
                while time >= !e do
                    op.reset (Tuple.singleton key_out (Int !eid)) ;
                    e := !e +. w ;
                    incr eid
                done
            ) ;
            op.next (Tuple.add key_out (Int !eid) p)
        ) ;
        reset = fun _ -> (
            op.reset (Tuple.singleton key_out (Int !eid)) ;
            e := 0.0 ;
            eid := 0
        ) ;
    }

(*
 * filter : (tuple -> bool) -> operator -> operator
 *
 * Passes only tuples where f applied to the tuple returns true
 *)
let filter f op =
    {
        next = (fun p -> if f p then op.next p) ;
        reset = (fun p -> op.reset p) ;
    }

(*
 * (filter utility)
 * key_geq_int : string -> int -> tuple -> bool
 *
 * Filter function for testing int values against a threshold
 *)
let key_geq_int key threshold (p:tuple) =
    (int_of_op_result (Tuple.find key p)) >= threshold

(*
 * (filter utility)
 * find_int : string -> tuple -> int
 *
 * Looks up the given key and converts to in
 * Note that if the key does not hold an int, this will raise an exception
 *)
let find_int key p =
    int_of_op_result (Tuple.find key p)

(*
 * (filter utility)
 * find_float : string -> tuple -> float
 *
 * Looks up the given key and converts to in
 * Note that if the key does not hold an int, this will raise an exception
 *)
let find_float key p =
    float_of_op_result (Tuple.find key p)

(*
 * map : (tuple -> tuple) -> operator -> operator
 *
 * Operator which applied the given function on all tuples
 * Passes resets, unchanged
 *)
let map f op =
    {
        next = (fun p -> op.next (f p)) ;
        reset = (fun p -> op.reset p) ;
    }

(*
 * groupby : (tuple -> tuple) -> (op_result -> tuple -> op_result) -> string -> operator -> operator
 *
 * Groups the received tuples according to canonic members returned by
 *   g : tuple -> tuple
 * Tuples in each group are folded (starting with Empty) by
 *   f : op_result -> tuple -> op_result
 * When reset, op is passed a tuple for each group containing the union of
 *   (i) the reset argument tuple,
 *   (ii) the result of g for that group, and
 *   (iii) a mapping from out_key to the result of the fold for that group
 *)
let groupby (g:tuple->tuple) (f:op_result->tuple->op_result) out_key op =
    let m = Hashtbl.create init_table_size in
    let e = ref 0 in
    {
        next = (fun p ->
            let k = g p in
            match Hashtbl.find_opt m k with
                | Some v -> Hashtbl.replace m k (f v p)
                | None -> Hashtbl.add m k (f Empty p)
        ) ;
        reset = (fun p ->
            e := !e + 1 ;
            Hashtbl.iter (fun k v ->
                let p' = Tuple.union (fun _ a _ -> Some a) p k in
                op.next (Tuple.add out_key v p')
            ) m ;
            op.reset p ;
            Hashtbl.clear m
        ) ;
    }


(*
 * (groupby utility)
 * get_keys : string list -> tuple -> tuple
 *
 * Returns a new tuple with only the keys included in the list keys
 *)
let get_keys keys (p:tuple) : tuple =
    Tuple.filter (fun k _ -> List.mem k keys) p

(*
 * (groupby utility)
 * single_group : tuple -> tuple
 *
 * Grouping function (g) that forms a single group
 *)
let single_group (_:tuple) : tuple = Tuple.empty

(*
 * (groupby utility)
 * count : op_result -> tuple -> op_result
 *
 * Reduction function (f) to count tuples
 *)
let count r (_:tuple) =
    match r with
        | Empty -> Int 1
        | Int i -> Int (i+1)
        | _ -> r

(*
 * (groupby utility)
 * sum : string -> op_result -> tuple -> op_result
 *
 * Reduction function (f) to sum values (assumed to be Int ()) of a given field
 *)
let sum s r (p:tuple) =
    match r with
        | Empty -> Int 0
        | Int i -> (
            match Tuple.find_opt s p with
                | Some (Int n) -> Int (i + n)
                | _ -> raise (Failure (sprintf "'sum' failed to find integer value for \"%s\"" s))
        )
        | _ -> r

(*
 * distinct : (tuple -> tuple) -> operator -> operator
 *
 * Returns a list of distinct elements (as determined by g) each epoch
 * 
 *)
let distinct (g:tuple->tuple) op =
    let m = Hashtbl.create init_table_size in
    let e = ref 0 in
    {
        next = (fun p ->
            let k = g p in
            Hashtbl.replace m k true
        ) ;
        reset = (fun p ->
            e := !e + 1 ;
            Hashtbl.iter (fun k _ ->
                let p' = Tuple.union (fun _ a _ -> Some a) p k in
                op.next p'
            ) m ;
            op.reset p ;
            Hashtbl.clear m
        ) ;
    }

(*
 * split : operator -> operator -> operator
 *
 * Just sends both next and reset directly to two downstream operators
 *)
let split l r =
    {
        next = (fun p -> (l.next p ; r.next p)) ;
        reset = (fun p -> (l.reset p ; r.reset p)) ;
    }

(*
 * join : (tuple -> tuple -> tuple option) -> operator -> (operator * operator)
 *
 * Initial shot at a join semantic that doesn't require maintining entire state
 * Functions left and right transform input tuples into a key,value pair of tuples
 * The key determines a canonical tuple against which the other stream will match
 * The value determines extra fields which should be saved and added when a match is made
 *
 * Requires tuples to have epoch id as int value in field referenced by eid_key.
 *)

let join ?(eid_key="eid") (left : tuple -> (tuple * tuple)) (right : tuple -> (tuple * tuple)) op =
    let m1 = Hashtbl.create init_table_size in
    let m2 = Hashtbl.create init_table_size in
    let e1 = ref 0 in
    let e2 = ref 0 in
    let o m m' e e' f =
        {
            next = (fun p ->
                let key, v = f p in
                let cur_e = find_int eid_key p in
                if cur_e > !e
                then while cur_e > !e do
                    if !e' > !e then op.reset (Tuple.singleton eid_key (Int !e)) ;
                    e := !e + 1
                done ;
                let k = Tuple.add eid_key (Int cur_e) key in
                match Hashtbl.find_opt m' k with
                    | Some v' -> (
                        let use_left = fun _ a _ -> Some a in
                        Hashtbl.remove m' k ;
                        op.next (Tuple.union use_left k (Tuple.union use_left v v')) ;
                    )
                    | None -> (
                        Hashtbl.add m k v ;
                    )
            ) ;
            reset = (fun p -> 
                let cur_e = find_int eid_key p in
                if cur_e > !e
                then while cur_e > !e do
                    if !e' > !e then op.reset (Tuple.singleton eid_key (Int !e)) ;
                    e := !e + 1
                done
            ) ;
        }
    in (o m1 m2 e1 e2 left, o m2 m1 e2 e1 right)


(*
 * (join utility)
 * get_keys_rename : (string * string) list -> tuple -> tuple
 *
 * Returns a new tuple with only the keys included in the first of each pair in keys
 * These keys are renamed to the second of each pair in keys
 * Use in conjunction with the join implementation above to get the "join left with right on left.x = right.y" kind of thing
 *)
let get_keys_rename renamings (p:tuple) : tuple =
    List.fold_left (fun a (k, k') ->
        match Tuple.find_opt k p with
            | Some v -> Tuple.add k' v a
            | None -> a
    ) Tuple.empty renamings
