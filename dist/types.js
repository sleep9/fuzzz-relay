export const protocolSchema = {
    type: 'object',
    properties: {
        version: { type: 'number' }
    },
    required: ['version'],
    additionalProperties: false
};
const pointSchema = {
    type: "object",
    properties: {
        x: { type: "number" },
        y: { type: "number" }
    },
    required: ["x", "y"],
    additionalProperties: false
};
export const textSchema = {
    type: "object",
    properties: {
        content: { type: 'string', maxLength: 512 },
        location: pointSchema,
        normalizedLocation: pointSchema,
        viewportWidth: { type: 'number' },
    },
    required: ['content', 'location', 'normalizedLocation', 'viewportWidth'],
    additionalProperties: false
};
/*
Instead of hardcoding "desktop" or pixel buckets into the protocol, consider storing the viewport
width that the drawing was created on:

Then each client can decide what "compatible" means.

const compatible =
    Math.abs(window.innerWidth - drawing.viewportWidth) <= 200;*/
export const strokeSchema = {
    type: "object",
    properties: {
        points: {
            type: "array",
            items: pointSchema,
            maxItems: 2048
        },
        color: {
            type: "string",
            pattern: "^#([0-9A-Fa-f]{6}|[0-9A-Fa-f]{8})$"
        },
        thickness: {
            type: "integer",
            enum: [1, 2, 3]
        },
        normalizedLocation: pointSchema,
        location: pointSchema,
        viewportWidth: {
            type: "number"
        }
    },
    required: [
        "points",
        "color",
        "thickness",
        "viewportWidth",
        "location",
        "normalizedLocation"
    ],
    additionalProperties: false
};
export const drawingSchema = {
    type: "object",
    properties: {
        strokes: {
            type: "array",
            items: strokeSchema,
            maxItems: 500
        }
    },
    required: [
        "strokes"
    ],
    additionalProperties: false
};
export const drawingDocumentSchema = {
    type: "object",
    properties: {
        texts: {
            anyOf: [
                {
                    type: "array",
                    items: textSchema
                },
                {
                    type: "string",
                    const: "stub"
                }
            ]
        },
        drawing: {
            anyOf: [
                drawingSchema,
                {
                    type: "string",
                    const: "stub"
                }
            ]
        }
    },
    required: ["texts", "drawing"],
    additionalProperties: false
};
export const postSchema = {
    type: "object",
    properties: {
        _protocol: protocolSchema,
        _pub: { type: "string" },
        _page: { type: "string" },
        url: { type: 'string' },
        payload: drawingDocumentSchema,
    },
    required: [
        "_protocol",
        "_pub",
        "_page",
        "url",
        "payload"
    ],
    additionalProperties: false
};
export const fuzzzAuthMessageSchema = {
    type: "object",
    oneOf: [
        {
            properties: {
                '#': { type: 'string' },
                dam: { const: "fuzzz-auth" },
                type: { const: "challenge" },
                challenge: {
                    type: "string",
                    pattern: "^[a-f0-9]{64}$"
                }
            },
            required: ["dam", "type", "challenge"],
            additionalProperties: false
        },
        {
            properties: {
                '#': { type: 'string' },
                dam: { const: "fuzzz-auth" },
                type: { const: "challenge-back" },
                challenge: {
                    type: "string",
                    pattern: "^[a-f0-9]{64}$"
                }
            },
            required: ["dam", "type", "challenge"],
            additionalProperties: false
        },
        {
            properties: {
                '#': { type: 'string' },
                dam: { const: "fuzzz-auth" },
                type: { const: "response" },
                pub: {
                    type: "string",
                    pattern: "^[A-Za-z0-9_-]{43}\\.[A-Za-z0-9_-]{43}$"
                },
                signature: {
                    type: "string",
                    minLength: 1,
                    maxLength: 4096
                }
            },
            required: ["dam", "type", "pub", "signature"],
            additionalProperties: false
        },
        {
            properties: {
                '#': { type: 'string' },
                dam: { const: "fuzzz-auth" },
                type: { const: "response-back" },
                pub: {
                    type: "string",
                    pattern: "^[A-Za-z0-9_-]{43}\\.[A-Za-z0-9_-]{43}$"
                },
                signature: {
                    type: "string",
                    minLength: 1,
                    maxLength: 4096
                }
            },
            required: ["dam", "type", "pub", "signature"],
            additionalProperties: false
        }
    ]
};
//# sourceMappingURL=types.js.map