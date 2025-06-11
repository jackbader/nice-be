exports.up = function (knex) {
    return knex.schema.createTable('sessions', function (table) {
        table.string('sid').primary();
        table.json('sess').notNull();
        table.timestamp('expire').notNull();
        table.index('expire');
    });
};

exports.down = function (knex) {
    return knex.schema.dropTable('sessions');
}; 